import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

test("fetch factories isolate and release their pooled connections", async (t) => {
  const fixtureDir = mkdtempSync(join(tmpdir(), "atlas-wasm-fetch-"));
  t.after(() => rmSync(fixtureDir, { recursive: true, force: true }));

  copyFileSync(
    fileURLToPath(new URL("../src/atls-fetch.js", import.meta.url)),
    join(fixtureDir, "atls-fetch.js")
  );
  writeFileSync(join(fixtureDir, "package.json"), '{"type":"module"}');
  writeFileSync(
    join(fixtureDir, "atlas_wasm.js"),
    [
      "export default async function init() {}",
      "export class AttestedStream {}",
      "export function mergeWithDefaultAppCompose(value) { return value; }",
      "export class AtlsHttp {",
      "  static instances = [];",
      "  static async connect() {",
      "    const instance = new AtlsHttp();",
      "    AtlsHttp.instances.push(instance);",
      "    return instance;",
      "  }",
      "  constructor() { this.closed = false; }",
      "  isReady() { return !this.closed; }",
      '  attestation() { return { trusted: true, teeType: "Tdx", tcbStatus: "UpToDate" }; }',
      '  async fetch() { return { status: 200, statusText: "OK", headers: {}, body: null }; }',
      "  close() { this.closed = true; }",
      "}",
      ""
    ].join("\n")
  );

  const {
    AtlsHttp,
    closeAllConnections,
    createAtlsFetch,
    getConnectionPoolStats
  } = await import(pathToFileURL(join(fixtureDir, "atls-fetch.js")).href);

  const options = {
    proxyUrl: "ws://127.0.0.1:9000",
    targetHost: "example.test:443",
    policy: { type: "dstack_tdx" }
  };
  const first = createAtlsFetch(options);
  const second = createAtlsFetch(options);

  await first("https://example.test/one");
  await first("https://example.test/two");
  assert.equal(AtlsHttp.instances.length, 1, "one factory reuses its connection");

  await second("https://example.test/three");
  assert.equal(getConnectionPoolStats().total, 2, "factories remain policy-isolated");

  first.close();
  assert.equal(getConnectionPoolStats().total, 1);
  assert.equal(AtlsHttp.instances[0].closed, true);
  assert.equal(AtlsHttp.instances[1].closed, false);

  first.close();
  assert.equal(getConnectionPoolStats().total, 1, "close is idempotent");

  await first("https://example.test/reconnected");
  assert.equal(AtlsHttp.instances.length, 3, "a closed factory reconnects");
  assert.equal(getConnectionPoolStats().total, 2);

  second.close();
  assert.equal(getConnectionPoolStats().total, 1);
  first.close();
  assert.equal(getConnectionPoolStats().total, 0);

  closeAllConnections();
});
