import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("WASM crate and npm package versions match", () => {
  const packageJson = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8")
  );
  const cargoToml = readFileSync(new URL("../Cargo.toml", import.meta.url), "utf8");
  const crateVersion = cargoToml.match(
    /^\s*version\s*=\s*"([^"]+)"\s*$/m
  )?.[1];

  assert.ok(crateVersion, "Cargo.toml package version must be present");
  assert.equal(packageJson.version, crateVersion);
});
