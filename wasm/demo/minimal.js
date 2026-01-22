/**
 * Minimal aTLS Demo - Shows TEE attestation with full verification
 */
import { init, createAtlsFetch, mergeWithDefaultAppCompose } from "../pkg/atls-fetch.js";

const PROXY = "ws://127.0.0.1:9000";
const output = document.getElementById("output");

function log(msg) {
  console.log(msg);
  output.textContent += msg + "\n";
}

// Docker compose content for vllm.concrete-security.com
// In production, this would be fetched or loaded from a config file
const VLLM_DOCKER_COMPOSE = `services:
  vllm:
    image: vllm/vllm-openai:v0.13.0
    container_name: vllm
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
    volumes:
      - huggingface-cache:/root/.cache/huggingface
    runtime: nvidia
    # No external ports - internal access only
    expose:
      - "8000"
    networks:
      - vllm
    command: >
      --model openai/gpt-oss-120b
      --tensor-parallel-size 1
      --gpu-memory-utilization 0.95
      --max-model-len 131072
      --max-num-seqs 8
      --reasoning-parser openai_gptoss
      --enable-auto-tool-choice
      --tool-call-parser openai
      --async-scheduling
      --allowed-origins []
    restart: unless-stopped
    healthcheck:
      start_interval: 1h30m # Allow up to 90 minutes for initial model loading
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Combined Nginx reverse proxy and Certificate Manager
  nginx-cert-manager:
    image: ghcr.io/concrete-security/cert-manager@sha256:92655a24060497516ea0cfd79b7fbfb599f13d303eb0c3e9c79cf8c5ee9cc1d1
    container_name: nginx-cert-manager
    ports:
      - "80:80"
      - "443:443"
    environment:
      - DOMAIN=vllm.concrete-security.com
      - DEV_MODE=false
      - LETSENCRYPT_STAGING=false
      # Used to versionize accounts: can change account by using another env variable
      # Useful in case an account reaches a rate limit
      - LETSENCRYPT_ACCOUNT_VERSION=v1
      # Force removal of existing certificate files on startup
      - FORCE_RM_CERT_FILES=false
      # Set log level
      - LOG_LEVEL=INFO
    volumes:
      - tls-certs-keys:/etc/nginx/ssl/
      - /var/run/dstack.sock:/var/run/dstack.sock
    networks:
      - vllm
      - attestation
      - auth
    restart: unless-stopped

  # Auth service for protected endpoints
  auth-service:
    image: ghcr.io/concrete-security/auth-service@sha256:f819c57d1648a4b4340fc296ef9872e43b70c7190d67a93820cf4f7b657d5310
    container_name: auth-service
    environment:
      - HOST=0.0.0.0
      - PORT=8081
      - AUTH_SERVICE_TOKEN=\${AUTH_SERVICE_TOKEN}
      - LOG_LEVEL=INFO
    expose:
      - "8081"
    networks:
      - auth
    restart: unless-stopped

  # TDX Attestation service
  attestation-service:
    image: ghcr.io/concrete-security/attestation-service@sha256:ad98abfe2d97fd2f25beba4a7e343376bce2ac0e8c3ed2ded97b38b06df12841
    container_name: attestation-service
    environment:
      - HOST=0.0.0.0
      - PORT=8080
      # Keep it to 1 if you want replication at the container orchestration level (see deploy.replicas)
      - WORKERS=1
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    expose:
      - "8080"
    networks:
      - attestation
    restart: unless-stopped
    deploy:
      mode: replicated
      # Keep it to 1 if you want replication at the process level (see env.WORKERS)
      replicas: 1

networks:
  vllm:
    driver: bridge
  attestation:
    driver: bridge
  auth:
    driver: bridge

volumes:
  # Used to store huggingface models
  huggingface-cache:
  # TLS certificates and keys
  tls-certs-keys:
`;

// Development policy - WARNING: disables runtime verification
// Use ONLY for development/testing, NEVER in production
const DEV_POLICY = {
  type: "dstack_tdx",
  disable_runtime_verification: true,  // DEV ONLY - skips bootchain/app_compose/os_image checks
  allowed_tcb_status: ["UpToDate", "SWHardeningNeeded", "OutOfDate"]
};

async function run() {
  log("Initializing WASM...");
  await init();
  log("WASM ready.\n");

  // Full production policy for vllm.concrete-security.com
  // Must be created after init() since mergeWithDefaultAppCompose requires WASM
  const VLLM_POLICY = {
    type: "dstack_tdx",
    expected_bootchain: {
      mrtd: "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
      rtmr0: "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418",
      rtmr1: "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
      rtmr2: "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57"
    },
    os_image_hash: "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a",
    app_compose: mergeWithDefaultAppCompose({
      docker_compose_file: VLLM_DOCKER_COMPOSE,
      allowed_envs: ["AUTH_SERVICE_TOKEN"]
    }),
    allowed_tcb_status: ["UpToDate", "SWHardeningNeeded"]
  };

  // 1. Try connecting to a non-TEE server with dev policy (will fail - no attestation)
  log("--- Attempting connection to google.com (non-TEE) ---");
  try {
    const badFetch = createAtlsFetch({
      proxyUrl: PROXY,
      targetHost: "google.com",
      policy: DEV_POLICY
    });
    await badFetch("/");
    log("Unexpected success!");
  } catch (error) {
    log("Expected failure: " + (error?.message || String(error)));
  }

  // 2. Connect to a real TEE server with full production policy
  log("\n--- Connecting to TEE server with full verification ---");
  try {
    const fetch = createAtlsFetch({
      proxyUrl: PROXY,
      targetHost: "vllm.concrete-security.com",
      policy: VLLM_POLICY
    });

    const response = await fetch("/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "openai/gpt-oss-120b",
        messages: [{ role: "user", content: "Say hello in 10 words or less" }],
        max_tokens: 50
      })
    });

    log("Attestation: " + JSON.stringify(response.attestation, null, 2));
    const data = await response.json();
    log("Response: " + JSON.stringify(data, null, 2));
  } catch (error) {
    log("Error: " + (error?.message || String(error)));
  }
}

run().catch(e => log("Fatal error: " + (e?.message || String(e))));
