/**
 * RA-TLS Browser AI Demo
 *
 * Demonstrates streaming chat completions through an attested TLS connection
 * to a vLLM instance running in a Trusted Execution Environment.
 */

import init from "../pkg/ratls_wasm.js";
import { createRatlsFetch } from "../pkg/ratls-fetch.js";

// DOM elements
const proxyInput = document.getElementById("proxy");
const targetInput = document.getElementById("target");
const modelInput = document.getElementById("model");
const apiKeyInput = document.getElementById("apiKey");
const promptInput = document.getElementById("prompt");
const sendButton = document.getElementById("send");
const clearButton = document.getElementById("clear");
const responseDiv = document.getElementById("response");
const attestationDiv = document.getElementById("attestation");

// State
let ratlsFetch = null;
let lastAttestation = null;
let isStreaming = false;

/**
 * Initialize the RA-TLS client with current configuration
 */
async function initializeClient() {
  const proxyUrl = proxyInput.value.trim();
  const target = targetInput.value.trim();

  if (!proxyUrl || !target) {
    throw new Error("Proxy URL and target are required");
  }

  // Ensure target has port
  const normalizedTarget = target.includes(":") ? target : `${target}:443`;
  const serverName = normalizedTarget.split(":")[0];

  // Initialize WASM module
  await init();

  // Create fetch with attestation callback
  ratlsFetch = createRatlsFetch({
    proxyUrl,
    targetHost: normalizedTarget,
    serverName,
    onAttestation: (attestation) => {
      lastAttestation = attestation;
      displayAttestation(attestation);
    }
  });

  return ratlsFetch;
}

/**
 * Display attestation status in the UI
 */
function displayAttestation(att) {
  if (!att) {
    attestationDiv.className = "";
    attestationDiv.innerHTML = '<span class="status">No attestation data</span>';
    return;
  }

  const isTrusted = att.trusted;
  const statusIcon = isTrusted ? "\u2713" : "\u2717";
  const statusText = isTrusted ? "TEE Verified" : "Verification Failed";

  attestationDiv.className = isTrusted ? "trusted" : "untrusted";
  attestationDiv.innerHTML = `
    <span class="status">${statusIcon} ${statusText}</span>
    <span class="details">TEE: ${att.teeType || "Unknown"} | TCB: ${att.tcbStatus || "Unknown"}</span>
  `;
}

/**
 * Parse SSE (Server-Sent Events) chunk and extract content
 */
function parseSSEChunk(chunk, onToken) {
  const lines = chunk.split("\n");

  for (const line of lines) {
    if (!line.startsWith("data: ")) continue;

    const data = line.slice(6).trim();
    if (data === "[DONE]") {
      return true; // Stream complete
    }

    try {
      const json = JSON.parse(data);
      const content = json.choices?.[0]?.delta?.content;
      if (content) {
        onToken(content);
      }
    } catch {
      // Ignore parse errors for partial chunks
    }
  }

  return false; // Stream continues
}

/**
 * Stream a chat completion request
 */
async function streamChat() {
  const prompt = promptInput.value.trim();
  const apiKey = apiKeyInput.value.trim();
  const model = modelInput.value.trim();

  if (!prompt) {
    showError("Please enter a prompt");
    return;
  }

  // Clear previous response
  responseDiv.textContent = "";
  responseDiv.className = "";
  isStreaming = true;
  sendButton.disabled = true;
  sendButton.innerHTML = 'Streaming<span class="loading"></span>';

  try {
    // Initialize client if needed (or reconnect with new config)
    if (!ratlsFetch) {
      attestationDiv.innerHTML = '<span class="status">Connecting...</span>';
      await initializeClient();
    }

    // Build headers
    const headers = {
      "Content-Type": "application/json"
    };
    if (apiKey) {
      headers["Authorization"] = `Bearer ${apiKey}`;
    }

    // Make the streaming request
    const response = await ratlsFetch("/v1/chat/completions", {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: model || "openai/gpt-oss-120b",
        messages: [{ role: "user", content: prompt }],
        stream: true
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    // Stream the response
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      // Process complete lines
      const lines = buffer.split("\n");
      buffer = lines.pop() || ""; // Keep incomplete line in buffer

      for (const line of lines) {
        if (!line.trim()) continue;

        if (line.startsWith("data: ")) {
          const data = line.slice(6).trim();
          if (data === "[DONE]") continue;

          try {
            const json = JSON.parse(data);
            const content = json.choices?.[0]?.delta?.content;
            if (content) {
              responseDiv.textContent += content;
            }
          } catch {
            // Partial JSON, ignore
          }
        }
      }
    }

    // Process any remaining buffer
    if (buffer.trim()) {
      parseSSEChunk(buffer, (token) => {
        responseDiv.textContent += token;
      });
    }

  } catch (error) {
    showError(error.message);
    // Reset client on error so next request reconnects
    ratlsFetch = null;
  } finally {
    isStreaming = false;
    sendButton.disabled = false;
    sendButton.textContent = "Send";
  }
}

/**
 * Show error message in response area
 */
function showError(message) {
  responseDiv.innerHTML = `<span class="error">Error: ${escapeHtml(message)}</span>`;
  responseDiv.className = "";
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Clear the response area
 */
function clearResponse() {
  responseDiv.textContent = "";
  responseDiv.className = "empty";
  responseDiv.textContent = "Response will appear here...";
}

// Event listeners
sendButton.addEventListener("click", streamChat);
clearButton.addEventListener("click", clearResponse);

promptInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.ctrlKey) {
    streamChat();
  }
});

// Reset client when config changes
proxyInput.addEventListener("change", () => { ratlsFetch = null; });
targetInput.addEventListener("change", () => { ratlsFetch = null; });

// Initialize on load
console.log("RA-TLS AI Demo loaded. Press Send to connect.");
