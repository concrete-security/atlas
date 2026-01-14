#!/usr/bin/env node
/**
 * RA-TLS Proxy Benchmark
 *
 * Scenarios:
 *   1. Standard TLS: Direct HTTPS to TEE (no proxy, no attestation)
 *   2. TLS + Proxy: WebSocket tunnel to TEE (no attestation)
 *   3. RA-TLS: Direct RA-TLS to TEE (no proxy, with attestation) via ratls-node
 *   4. RA-TLS + Proxy: WebSocket tunnel with full attestation via ratls-wasm
 *
 * Usage: node benchmark.mjs [iterations]
 */

import https from 'https';
import tls from 'tls';
import fs from 'fs';
import { WebSocket } from 'ws';
import { Duplex } from 'stream';
import { performance } from 'perf_hooks';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Polyfill WebSocket for WASM module (it expects browser WebSocket API)
globalThis.WebSocket = WebSocket;

// Load ratls-node library (for direct RA-TLS)
const ratlsNodePath = path.join(__dirname, '..', '..', '..', 'node');
const { createRatlsFetch } = await import(path.join(ratlsNodePath, 'ratls-fetch.js'));

// Load and initialize ratls-wasm library (for RA-TLS + Proxy)
const wasmPkgPath = path.join(__dirname, '..', '..', 'pkg');
const wasmModule = await import(path.join(wasmPkgPath, 'ratls_wasm.js'));
const wasmBuffer = fs.readFileSync(path.join(wasmPkgPath, 'ratls_wasm_bg.wasm'));
await wasmModule.default(wasmBuffer);
const { RatlsHttp } = wasmModule;

const ITERATIONS = parseInt(process.argv[2] || '5', 10);

// Configuration
const VLLM_HOST = 'vllm.concrete-security.com';
const VLLM_PORT = 443;
const PROXY_URL = 'ws://ec2-13-56-181-124.us-west-1.compute.amazonaws.com:9000/tunnel';

// Request that generates a predictable number of tokens
const CHAT_REQUEST = {
    model: 'openai/gpt-oss-120b',
    messages: [{ role: 'user', content: 'Write exactly 100 words about artificial intelligence.' }],
    max_tokens: 200,
    temperature: 0.7,
    stream: true,
    stream_options: { include_usage: true },
};

/**
 * Parse SSE stream to extract TTFT and token count
 */
function createSSEParser(startTime) {
    let ttft = null;
    let usage = null;
    let buffer = '';

    return {
        feed(chunk) {
            buffer += chunk;
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const jsonStr = line.slice(6).trim();
                    if (jsonStr === '[DONE]') continue;

                    try {
                        const parsed = JSON.parse(jsonStr);

                        if (ttft === null) {
                            const delta = parsed.choices?.[0]?.delta;
                            const hasContent = delta?.content || delta?.reasoning_content;
                            if (hasContent) {
                                ttft = performance.now() - startTime;
                            }
                        }

                        if (parsed.usage) {
                            usage = parsed.usage;
                        }
                    } catch {}
                }
            }
        },
        getResults() {
            return { ttft, usage };
        }
    };
}

/**
 * Scenario 1: Standard TLS (Direct HTTPS to TEE)
 */
async function standardTls() {
    const startTime = performance.now();
    const parser = createSSEParser(startTime);

    return new Promise((resolve, reject) => {
        const body = JSON.stringify(CHAT_REQUEST);

        const req = https.request({
            hostname: VLLM_HOST,
            port: VLLM_PORT,
            path: '/v1/chat/completions',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body),
            },
            timeout: 120000,
        }, (res) => {
            res.on('data', chunk => parser.feed(chunk.toString()));
            res.on('end', () => {
                const totalTime = performance.now() - startTime;
                const { ttft, usage } = parser.getResults();
                const tokens = usage?.completion_tokens || 0;
                const throughput = tokens > 0 ? (tokens / (totalTime / 1000)) : 0;

                resolve({
                    success: res.statusCode === 200 && tokens > 0,
                    ttft,
                    totalTime,
                    tokens,
                    throughput,
                });
            });
        });

        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.write(body);
        req.end();
    });
}

/**
 * Create WebSocket duplex stream
 */
function createWsStream(ws) {
    const stream = new Duplex({
        read() {},
        write(chunk, encoding, callback) {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(chunk, callback);
            } else {
                callback(new Error('WebSocket closed'));
            }
        },
    });
    ws.on('message', data => stream.push(Buffer.from(data)));
    ws.on('close', () => stream.push(null));
    ws.on('error', err => stream.destroy(err));
    return stream;
}

/**
 * HTTP request over TLS socket with streaming
 */
function httpOverTls(tlsSocket, method, path, body, onData) {
    return new Promise((resolve, reject) => {
        const headers = [
            `${method} ${path} HTTP/1.1`,
            `Host: ${VLLM_HOST}`,
            'Content-Type: application/json',
            `Content-Length: ${Buffer.byteLength(body)}`,
            'Connection: close',
            '', ''
        ].join('\r\n');

        tlsSocket.write(headers + body);

        let headersDone = false;
        let buffer = '';
        let statusCode = 0;

        tlsSocket.on('data', chunk => {
            buffer += chunk.toString();

            if (!headersDone) {
                const idx = buffer.indexOf('\r\n\r\n');
                if (idx !== -1) {
                    const headerPart = buffer.substring(0, idx);
                    const match = headerPart.match(/HTTP\/\d\.\d (\d+)/);
                    statusCode = match ? parseInt(match[1]) : 0;
                    headersDone = true;

                    const bodyPart = buffer.substring(idx + 4);
                    buffer = '';
                    if (bodyPart) onData(bodyPart);
                }
            } else {
                onData(buffer);
                buffer = '';
            }
        });

        tlsSocket.on('end', () => resolve({ statusCode }));
        tlsSocket.on('error', reject);
    });
}

/**
 * Scenario 2: TLS + Proxy (no attestation)
 */
async function proxyTls() {
    const startTime = performance.now();
    const parser = createSSEParser(startTime);

    return new Promise((resolve, reject) => {
        const ws = new WebSocket(PROXY_URL);
        ws.binaryType = 'nodebuffer';

        const cleanup = () => { try { ws.close(); } catch {} };

        ws.on('open', () => {
            const wsStream = createWsStream(ws);

            const tlsSocket = tls.connect({
                socket: wsStream,
                servername: VLLM_HOST,
                rejectUnauthorized: true,
            }, async () => {
                try {
                    const body = JSON.stringify(CHAT_REQUEST);
                    const res = await httpOverTls(tlsSocket, 'POST', '/v1/chat/completions', body,
                        chunk => parser.feed(chunk));

                    cleanup();
                    const totalTime = performance.now() - startTime;
                    const { ttft, usage } = parser.getResults();
                    const tokens = usage?.completion_tokens || 0;
                    const throughput = tokens > 0 ? (tokens / (totalTime / 1000)) : 0;

                    resolve({
                        success: res.statusCode === 200 && tokens > 0,
                        ttft,
                        totalTime,
                        tokens,
                        throughput,
                    });
                } catch (err) {
                    cleanup();
                    reject(err);
                }
            });

            tlsSocket.on('error', err => { cleanup(); reject(err); });
        });

        ws.on('error', reject);
        setTimeout(() => { cleanup(); reject(new Error('Timeout')); }, 120000);
    });
}

/**
 * Scenario 3: RA-TLS direct (full attestation via ratls-node, no proxy)
 */
async function directRatls() {
    const startTime = performance.now();
    let attestationTime = null;

    // Create RA-TLS fetch using ratls-node (direct TCP connection)
    const policy = {
        type: 'dstack_tdx',
        disable_runtime_verification: true,
        allowed_tcb_status: ['UpToDate', 'SWHardeningNeeded', 'OutOfDate', 'ConfigurationNeeded'],
    };

    const fetch = createRatlsFetch({
        target: VLLM_HOST,
        policy,
        onAttestation: () => {
            attestationTime = performance.now() - startTime;
        }
    });

    // Make streaming request
    const res = await fetch('/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(CHAT_REQUEST),
    });

    if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
    }

    // Parse SSE stream
    const parser = createSSEParser(startTime);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        parser.feed(decoder.decode(value, { stream: true }));
    }

    const totalTime = performance.now() - startTime;
    const { ttft, usage } = parser.getResults();
    const tokens = usage?.completion_tokens || 0;
    const throughput = tokens > 0 ? (tokens / (totalTime / 1000)) : 0;

    return {
        success: tokens > 0,
        ttft,
        totalTime,
        tokens,
        throughput,
        attestationTime,
    };
}

/**
 * Scenario 4: RA-TLS + Proxy (full attestation via ratls-wasm)
 */
async function proxyRatls() {
    const startTime = performance.now();
    let attestationTime = null;

    // Build proxy URL with target
    const wsUrl = `${PROXY_URL}?target=${VLLM_HOST}:443`;

    // Connect and perform RA-TLS handshake via WASM
    const http = await RatlsHttp.connect(wsUrl, VLLM_HOST);

    // Get attestation
    const attestation = http.attestation();
    attestationTime = performance.now() - startTime;

    // Make streaming request
    const body = JSON.stringify(CHAT_REQUEST);
    const bodyBytes = new TextEncoder().encode(body);

    const result = await http.fetch(
        'POST',
        '/v1/chat/completions',
        VLLM_HOST,
        [['Content-Type', 'application/json']],
        bodyBytes
    );

    if (result.status !== 200) {
        throw new Error(`HTTP ${result.status}`);
    }

    // Parse SSE stream
    const parser = createSSEParser(startTime);
    const reader = result.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        parser.feed(decoder.decode(value, { stream: true }));
    }

    const totalTime = performance.now() - startTime;
    const { ttft, usage } = parser.getResults();
    const tokens = usage?.completion_tokens || 0;
    const throughput = tokens > 0 ? (tokens / (totalTime / 1000)) : 0;

    return {
        success: tokens > 0,
        ttft,
        totalTime,
        tokens,
        throughput,
        attestationTime,
        attestation: {
            teeType: attestation?.teeType,
            tcbStatus: attestation?.tcbStatus,
        },
    };
}

// Statistics
function stats(arr) {
    if (arr.length === 0) return { mean: 'N/A', p50: 'N/A', p95: 'N/A' };
    const sorted = [...arr].sort((a, b) => a - b);
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const p50 = sorted[Math.floor(arr.length * 0.5)];
    const p95 = sorted[Math.floor(arr.length * 0.95)] || sorted[sorted.length - 1];
    return { mean: mean.toFixed(1), p50: p50.toFixed(1), p95: p95.toFixed(1) };
}

async function benchmark(name, fn, iterations) {
    const results = { ttft: [], total: [], tokens: [], throughput: [], genThroughput: [], attestation: [] };
    let success = 0;

    process.stdout.write(`  ${name}: `);

    for (let i = 0; i < iterations; i++) {
        process.stdout.write('.');
        try {
            const r = await fn();
            if (r.success) {
                results.ttft.push(r.ttft);
                results.total.push(r.totalTime);
                results.tokens.push(r.tokens);
                results.throughput.push(r.throughput);
                const genTime = r.totalTime - r.ttft;
                const genThru = genTime > 0 ? (r.tokens / (genTime / 1000)) : 0;
                results.genThroughput.push(genThru);
                if (r.attestationTime) results.attestation.push(r.attestationTime);
                success++;
            }
        } catch (e) {
            process.stdout.write('x');
        }
        await new Promise(r => setTimeout(r, 500));
    }

    console.log(` ${success}/${iterations}`);
    return results;
}

async function main() {
    console.log('RA-TLS Proxy Benchmark');
    console.log('═'.repeat(60));
    console.log(`Target: ${VLLM_HOST}:${VLLM_PORT}`);
    console.log(`Proxy:  ${PROXY_URL}`);
    console.log(`Iterations: ${ITERATIONS}`);
    console.log('');

    // Warmup
    console.log('Warming up...');
    try {
        const r = await standardTls();
        console.log(`  Standard TLS: ${r.tokens} tokens, ${r.totalTime.toFixed(0)}ms`);
    } catch (e) { console.log(`  Standard TLS: FAILED - ${e.message}`); }

    try {
        const r = await proxyTls();
        console.log(`  TLS + Proxy: ${r.tokens} tokens, ${r.totalTime.toFixed(0)}ms`);
    } catch (e) { console.log(`  TLS + Proxy: FAILED - ${e.message}`); }

    try {
        const r = await directRatls();
        console.log(`  RA-TLS: ${r.tokens} tokens, attestation=${r.attestationTime?.toFixed(0)}ms, total=${r.totalTime.toFixed(0)}ms`);
    } catch (e) { console.log(`  RA-TLS: FAILED - ${e.message}`); }

    try {
        const r = await proxyRatls();
        console.log(`  RA-TLS + Proxy: ${r.tokens} tokens, attestation=${r.attestationTime?.toFixed(0)}ms (${r.attestation?.teeType}/${r.attestation?.tcbStatus}), total=${r.totalTime.toFixed(0)}ms`);
    } catch (e) { console.log(`  RA-TLS + Proxy: FAILED - ${e.message}`); }
    console.log('');

    // Run benchmarks
    console.log('Running benchmarks...');
    const std = await benchmark('Standard TLS', standardTls, ITERATIONS);
    const proxy = await benchmark('TLS + Proxy', proxyTls, ITERATIONS);
    const ratlsDirect = await benchmark('RA-TLS', directRatls, ITERATIONS);
    const ratlsProxy = await benchmark('RA-TLS + Proxy', proxyRatls, ITERATIONS);

    // Results
    console.log('\n' + '═'.repeat(80));
    console.log('RESULTS');
    console.log('═'.repeat(80));

    const ttft1 = stats(std.ttft), ttft2 = stats(proxy.ttft);
    const ttft3 = stats(ratlsDirect.ttft), ttft4 = stats(ratlsProxy.ttft);
    const thru1 = stats(std.throughput), thru2 = stats(proxy.throughput);
    const thru3 = stats(ratlsDirect.throughput), thru4 = stats(ratlsProxy.throughput);
    const gen1 = stats(std.genThroughput), gen2 = stats(proxy.genThroughput);
    const gen3 = stats(ratlsDirect.genThroughput), gen4 = stats(ratlsProxy.genThroughput);
    const total1 = stats(std.total), total2 = stats(proxy.total);
    const total3 = stats(ratlsDirect.total), total4 = stats(ratlsProxy.total);
    const att3 = stats(ratlsDirect.attestation), att4 = stats(ratlsProxy.attestation);

    const avgTok = arr => arr.length ? (arr.reduce((a,b)=>a+b,0)/arr.length).toFixed(0) : 'N/A';

    console.log('\n┌─────────────────────┬──────────────┬──────────────┬──────────────┬──────────────┐');
    console.log('│ Metric              │ Standard TLS │ TLS + Proxy  │ RA-TLS       │ RA-TLS+Proxy │');
    console.log('├─────────────────────┼──────────────┼──────────────┼──────────────┼──────────────┤');
    console.log(`│ TTFT mean           │ ${ttft1.mean.padStart(9)}ms │ ${ttft2.mean.padStart(9)}ms │ ${ttft3.mean.padStart(9)}ms │ ${ttft4.mean.padStart(9)}ms │`);
    console.log(`│ TTFT p50            │ ${ttft1.p50.padStart(9)}ms │ ${ttft2.p50.padStart(9)}ms │ ${ttft3.p50.padStart(9)}ms │ ${ttft4.p50.padStart(9)}ms │`);
    console.log(`│ TTFT p95            │ ${ttft1.p95.padStart(9)}ms │ ${ttft2.p95.padStart(9)}ms │ ${ttft3.p95.padStart(9)}ms │ ${ttft4.p95.padStart(9)}ms │`);
    console.log('├─────────────────────┼──────────────┼──────────────┼──────────────┼──────────────┤');
    console.log(`│ Eff. Throughput     │ ${thru1.mean.padStart(8)} t/s │ ${thru2.mean.padStart(8)} t/s │ ${thru3.mean.padStart(8)} t/s │ ${thru4.mean.padStart(8)} t/s │`);
    console.log(`│ Gen. Throughput     │ ${gen1.mean.padStart(8)} t/s │ ${gen2.mean.padStart(8)} t/s │ ${gen3.mean.padStart(8)} t/s │ ${gen4.mean.padStart(8)} t/s │`);
    console.log('├─────────────────────┼──────────────┼──────────────┼──────────────┼──────────────┤');
    console.log(`│ Total time mean     │ ${total1.mean.padStart(9)}ms │ ${total2.mean.padStart(9)}ms │ ${total3.mean.padStart(9)}ms │ ${total4.mean.padStart(9)}ms │`);
    console.log(`│ Attestation mean    │          N/A │          N/A │ ${att3.mean.padStart(9)}ms │ ${att4.mean.padStart(9)}ms │`);
    console.log(`│ Tokens (avg)        │ ${avgTok(std.tokens).padStart(12)} │ ${avgTok(proxy.tokens).padStart(12)} │ ${avgTok(ratlsDirect.tokens).padStart(12)} │ ${avgTok(ratlsProxy.tokens).padStart(12)} │`);
    console.log('└─────────────────────┴──────────────┴──────────────┴──────────────┴──────────────┘');

    // Overhead analysis
    if (std.ttft.length && proxy.ttft.length && ratlsDirect.ttft.length && ratlsProxy.ttft.length) {
        const baseT = std.ttft.reduce((a,b)=>a+b,0) / std.ttft.length;
        const proxyT = proxy.ttft.reduce((a,b)=>a+b,0) / proxy.ttft.length;
        const ratlsDirectT = ratlsDirect.ttft.reduce((a,b)=>a+b,0) / ratlsDirect.ttft.length;
        const ratlsProxyT = ratlsProxy.ttft.reduce((a,b)=>a+b,0) / ratlsProxy.ttft.length;

        console.log('\n' + '─'.repeat(80));
        console.log('OVERHEAD ANALYSIS (TTFT vs Standard TLS)');
        console.log('─'.repeat(80));
        console.log(`Proxy overhead:       TLS+Proxy - Standard     = +${(proxyT - baseT).toFixed(0)}ms`);
        console.log(`RA-TLS overhead:      RA-TLS - Standard        = +${(ratlsDirectT - baseT).toFixed(0)}ms`);
        console.log(`RA-TLS+Proxy:         RA-TLS+Proxy - Standard  = +${(ratlsProxyT - baseT).toFixed(0)}ms`);
        console.log('─'.repeat(80));
        console.log('Note: RA-TLS uses ratls-node, RA-TLS+Proxy uses ratls-wasm (different implementations)');
    }

    console.log('\nNotes:');
    console.log('  - Standard TLS: Direct HTTPS connection to TEE (Node.js built-in)');
    console.log('  - TLS + Proxy: WebSocket tunnel, no attestation (Node.js built-in TLS)');
    console.log('  - RA-TLS: Direct RA-TLS connection via ratls-node (full attestation)');
    console.log('  - RA-TLS + Proxy: WebSocket tunnel via ratls-wasm (full attestation)');
    console.log('  - Gen. Throughput excludes TTFT (pure generation speed)');
}

main().catch(console.error);
