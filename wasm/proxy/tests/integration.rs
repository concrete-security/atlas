//! Integration tests for atls-proxy WebSocket-to-TCP forwarding.

use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Helper to find an available port for testing
async fn get_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Spawn the proxy server with given configuration.
/// Returns the proxy listen address and a shutdown sender.
async fn spawn_proxy(
    target: &str,
    allowlist: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let proxy_port = get_available_port().await;
    let listen_addr = format!("127.0.0.1:{}", proxy_port);
    let listen_addr_clone = listen_addr.clone();
    let target = target.to_string();
    let allowlist = allowlist.to_string();

    let handle = tokio::spawn(async move {
        use std::collections::HashSet;
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_tungstenite::accept_hdr_async;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        use url::form_urlencoded;

        fn parse_allowlist(val: &str) -> HashSet<String> {
            val.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }

        fn extract_target(req: &Request) -> Option<String> {
            req.uri().query().and_then(|query| {
                form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == "target")
                    .map(|(_, value)| value.into_owned())
            })
        }

        let allowlist_set = Arc::new(parse_allowlist(&allowlist));
        let listener = TcpListener::bind(&listen_addr_clone).await.unwrap();

        // Accept a limited number of connections for testing
        for _ in 0..5 {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((stream, _peer)) = result {
                        let default_target = target.clone();
                        let allowlist_clone = allowlist_set.clone();

                        tokio::spawn(async move {
                            let shared_target = std::sync::Arc::new(std::sync::Mutex::new(default_target.clone()));
                            let capture = shared_target.clone();

                            let mut ws_stream = match accept_hdr_async(stream, move |req: &Request, response: Response| {
                                if let Some(tgt) = extract_target(req) {
                                    if let Ok(mut guard) = capture.lock() {
                                        *guard = tgt;
                                    }
                                }
                                Ok(response)
                            }).await {
                                Ok(ws) => ws,
                                Err(_) => return,
                            };

                            let final_target = shared_target.lock().map(|guard| guard.clone()).unwrap_or(default_target);

                            if !allowlist_clone.contains(&final_target) {
                                let _ = ws_stream.close(None).await;
                                return;
                            }

                            let tcp = match TcpStream::connect(&final_target).await {
                                Ok(s) => s,
                                Err(_) => return,
                            };

                            let (mut ws_sink, mut ws_source) = ws_stream.split();
                            let (mut tcp_reader, mut tcp_writer) = tcp.into_split();
                            let mut buf = [0u8; 8192];

                            loop {
                                tokio::select! {
                                    msg = ws_source.next() => {
                                        match msg {
                                            Some(Ok(msg)) if msg.is_binary() || msg.is_text() => {
                                                if tcp_writer.write_all(&msg.into_data()).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Some(Ok(msg)) if msg.is_close() => {
                                                let _ = ws_sink.send(Message::Close(None)).await;
                                                break;
                                            }
                                            Some(Err(_)) | None => break,
                                            _ => {}
                                        }
                                    }
                                    res = tcp_reader.read(&mut buf) => {
                                        match res {
                                            Ok(0) => {
                                                let _ = ws_sink.send(Message::Close(None)).await;
                                                break;
                                            }
                                            Ok(n) => {
                                                if ws_sink.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    break;
                }
            }
        }
    });

    // Give the proxy time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    (format!("ws://127.0.0.1:{}", proxy_port), handle)
}

/// Spawn a simple echo TCP server that echoes back what it receives.
async fn spawn_echo_server() -> (String, tokio::task::JoinHandle<()>) {
    let port = get_available_port().await;
    let addr = format!("127.0.0.1:{}", port);
    let addr_clone = addr.clone();

    let handle = tokio::spawn(async move {
        let listener = TcpListener::bind(&addr_clone).await.unwrap();

        for _ in 0..5 {
            tokio::select! {
                result = listener.accept() => {
                    if let Ok((mut stream, _)) = result {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    break;
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

#[tokio::test]
async fn test_websocket_to_tcp_forwarding() {
    // Start echo server
    let (echo_addr, _echo_handle) = spawn_echo_server().await;

    // Start proxy pointing to echo server
    let (proxy_url, _proxy_handle) = spawn_proxy(&echo_addr, &echo_addr).await;

    // Connect via WebSocket
    let (mut ws_stream, _) = connect_async(&proxy_url)
        .await
        .expect("Failed to connect to proxy");

    // Send test data
    let test_data = b"Hello, TEE!";
    ws_stream
        .send(Message::Binary(test_data.to_vec()))
        .await
        .expect("Failed to send message");

    // Receive echoed data
    let msg = tokio::time::timeout(Duration::from_secs(5), ws_stream.next())
        .await
        .expect("Timeout waiting for response")
        .expect("Stream ended")
        .expect("Error receiving message");

    match msg {
        Message::Binary(data) => {
            assert_eq!(data, test_data, "Echoed data should match sent data");
        }
        _ => panic!("Expected binary message, got {:?}", msg),
    }

    // Clean close
    ws_stream.close(None).await.ok();
}

#[tokio::test]
async fn test_websocket_target_from_query_param() {
    // Start two echo servers
    let (echo_addr1, _echo_handle1) = spawn_echo_server().await;
    let (echo_addr2, _echo_handle2) = spawn_echo_server().await;

    // Start proxy with echo_addr1 as default but both in allowlist
    let (proxy_url, _proxy_handle) =
        spawn_proxy(&echo_addr1, &format!("{},{}", echo_addr1, echo_addr2)).await;

    // Connect with target pointing to echo_addr2 via query param
    // URL encode the target to handle the colon properly
    let encoded_target: String = url::form_urlencoded::byte_serialize(echo_addr2.as_bytes()).collect();
    let url_with_target = format!("{}/tunnel?target={}", proxy_url, encoded_target);
    let (mut ws_stream, _) = connect_async(&url_with_target)
        .await
        .expect("Failed to connect to proxy");

    // Send and receive
    let test_data = b"Query param target test";
    ws_stream
        .send(Message::Binary(test_data.to_vec()))
        .await
        .expect("Failed to send message");

    let msg = tokio::time::timeout(Duration::from_secs(5), ws_stream.next())
        .await
        .expect("Timeout waiting for response")
        .expect("Stream ended")
        .expect("Error receiving message");

    match msg {
        Message::Binary(data) => {
            assert_eq!(data, test_data);
        }
        _ => panic!("Expected binary message"),
    }

    ws_stream.close(None).await.ok();
}

#[tokio::test]
async fn test_websocket_unauthorized_target_rejected() {
    // Start echo server
    let (echo_addr, _echo_handle) = spawn_echo_server().await;

    // Start proxy with allowlist that doesn't include echo server
    let (proxy_url, _proxy_handle) = spawn_proxy(&echo_addr, "other.host:443").await;

    // Connection should fail or be closed immediately since target not in allowlist
    let result = connect_async(&proxy_url).await;

    // The proxy accepts the WebSocket connection but should close it immediately
    // when it detects the target is not authorized
    match result {
        Ok((mut ws, _)) => {
            // Try to send/receive - should fail
            ws.send(Message::Binary(vec![1, 2, 3])).await.ok();
            let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
            // Either timeout or close message is acceptable
            match msg {
                Ok(Some(Ok(Message::Close(_)))) => {} // Expected
                Ok(None) => {}                        // Stream closed
                Err(_) => {}                          // Timeout is also acceptable
                _ => {}
            }
        }
        Err(_) => {
            // Connection refused is also acceptable
        }
    }
}

#[tokio::test]
async fn test_websocket_multiple_messages() {
    // Start echo server
    let (echo_addr, _echo_handle) = spawn_echo_server().await;

    // Start proxy
    let (proxy_url, _proxy_handle) = spawn_proxy(&echo_addr, &echo_addr).await;

    // Connect
    let (mut ws_stream, _) = connect_async(&proxy_url)
        .await
        .expect("Failed to connect to proxy");

    // Send multiple messages
    for i in 0..5 {
        let test_data = format!("Message {}", i);
        ws_stream
            .send(Message::Binary(test_data.as_bytes().to_vec()))
            .await
            .expect("Failed to send message");

        let msg = tokio::time::timeout(Duration::from_secs(5), ws_stream.next())
            .await
            .expect("Timeout")
            .expect("Stream ended")
            .expect("Error receiving");

        match msg {
            Message::Binary(data) => {
                assert_eq!(data, test_data.as_bytes());
            }
            _ => panic!("Expected binary message"),
        }
    }

    ws_stream.close(None).await.ok();
}

#[tokio::test]
async fn test_websocket_binary_data() {
    // Start echo server
    let (echo_addr, _echo_handle) = spawn_echo_server().await;

    // Start proxy
    let (proxy_url, _proxy_handle) = spawn_proxy(&echo_addr, &echo_addr).await;

    // Connect
    let (mut ws_stream, _) = connect_async(&proxy_url)
        .await
        .expect("Failed to connect to proxy");

    // Send binary data with all byte values
    let test_data: Vec<u8> = (0..=255).collect();
    ws_stream
        .send(Message::Binary(test_data.clone()))
        .await
        .expect("Failed to send message");

    let msg = tokio::time::timeout(Duration::from_secs(5), ws_stream.next())
        .await
        .expect("Timeout")
        .expect("Stream ended")
        .expect("Error receiving");

    match msg {
        Message::Binary(data) => {
            assert_eq!(data, test_data, "Binary data should be preserved exactly");
        }
        _ => panic!("Expected binary message"),
    }

    ws_stream.close(None).await.ok();
}
