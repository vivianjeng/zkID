/**
 * End-to-end test using a real issued vc+sd-jwt credential.
 *
 * The credential has no attached disclosures (the issuer provided only the
 * bare JWT; the _sd array holds one digest but the disclosure string is not
 * in our possession).  We therefore run the JWT circuit with an empty
 * disclosure set — all claim slots are zero-padded.  The circuit still:
 *   1. Verifies the ES256 issuer signature
 *   2. Extracts the device binding public key (cnf.jwk) from the payload
 *
 * The Show circuit is intentionally skipped: it requires signing a verifier
 * nonce with the device private key, which we do not have.
 *
 * Proof pipeline uses the 2k circuit size — the credential's message length
 * (1920 SHA-256-padded bytes) fits within the 2k limit (2048).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { writeFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { execFile } from "child_process";
import { promisify } from "util";

import {
  WitnessCalculator,
  Credential,
  buildJwtCircuitInputs,
  base64urlToBigInt,
  DEFAULT_JWT_PARAMS,
} from "../src/index.js";
import type { EcdsaPublicKey } from "../src/index.js";

const execFileAsync = promisify(execFile);

// 2k circuit params — smallest size that fits this credential
const JWT_2K_PARAMS = {
  maxMessageLength: 2048,
  maxB64PayloadLength: 2000,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, "..", "assets");

// ---------------------------------------------------------------------------
// Credential under test
// ---------------------------------------------------------------------------

const CREDENTIAL_JWT =
  "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9" +
  ".eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxZDI0b3g3cVp4NmJ2TndENzNja2lXZkRCQzV5NHpnckNMdVRuMXBNQnpGWFBIdHVXUDEyY1lQRmRSdjQ5MlE4WDFYZVoyeVg3U1pZWDloV1RaV0F2QXpUWFMydkJIakI2QnhxOGZGeEd5ZTRTd1dtcWdaODZRU3lkd2hoRHU5eTZLV2dlZDlhVkFlTFpjbUNXTHFzZ21CVUJDaG50SGdvSHhtczVadXZDTFUiLCJuYmYiOjE3Nzg1MTUyMDAsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUzWkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJqd2siOnsieSI6Ilpza1oyQ2dmWWpDZWpDaUFNdzNnZ3JReHZ2TlJNLUpOTEtWU0xEcjNjdWsiLCJ4IjoiVkZCd1k3cFg3ZEI0RDF5YXNwYVRIM0luTElLeURCUUU5OFRSVzNISGRmbyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYifX0sImV4cCI6MTc3OTIwNjM5OSwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW8iXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvMDAwMDAwMDBfZGVtby9yMCMxOCIsInN0YXR1c0xpc3RJbmRleCI6IjE4Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9zdGF0dXMtbGlzdC8wMDAwMDAwMF9kZW1vL3IwIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW8vVjEvZjFlYTllMTQtNzdhNy00MzRlLWI3MDEtZjhkYjViMGMzMDJkIiwidHlwZSI6Ikpzb25TY2hlbWEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIjdqcnJDdFlsamJYQ3ZvckpZUXlyNnNZVDVVTzBoYW9ZT1BnUGtGc0U4WkkiXSwiX3NkX2FsZyI6InNoYS0yNTYifX0sIm5vbmNlIjoiR1c4N1dZOTAiLCJqdGkiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzExMzdkN2RmLTU3YzgtNDU3NS05NjViLTgxZjNkOTE4NTg4OSJ9" +
  ".uaSHN7nXORtfcU9PjSaDPdEZ7kqvFbz5sZsqjT2iIFCMPVwgSp8OcoqUSYqu2_TLpYVEk3niIGHp5aZoBwmGHw";

// No disclosures are attached to this credential — the SD-JWT was provided
// without the ~disclosure~ segments.
const DISCLOSURES: string[] = [];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function fetchIssuerKey(jku: string, kid: string): Promise<EcdsaPublicKey> {
  const res = await fetch(jku);
  if (!res.ok) throw new Error(`JWK fetch failed: ${res.status} ${res.statusText}`);
  const jwks = await res.json() as { keys: Array<Record<string, string>> };
  const key = jwks.keys.find((k) => k["kid"] === kid);
  if (!key) throw new Error(`Key '${kid}' not found in JWK Set`);
  return { kty: "EC", crv: "P-256", x: key["x"]!, y: key["y"]!, kid };
}

// Paths for the ecdsa-spartan2 Rust binary and its keys
const SPARTAN_DIR = join(__dirname, "..", "..", "ecdsa-spartan2");
const SPARTAN_BIN = join(SPARTAN_DIR, "target", "release", "ecdsa-spartan2");
const DYLIB_DIR = (() => {
  const buildDir = join(SPARTAN_DIR, "target", "release", "build");
  if (!existsSync(buildDir)) return undefined;
  for (const entry of readdirSync(buildDir)) {
    const candidate = join(buildDir, entry, "out", "witnesscalc", "build_witnesscalc", "src");
    if (existsSync(join(candidate, "libwitnesscalc_jwt.dylib"))) return candidate;
    if (existsSync(join(candidate, "libwitnesscalc_jwt_2k.dylib"))) return candidate;
  }
  return undefined;
})();

async function runSpartan(args: string[]): Promise<string> {
  const { stdout, stderr } = await execFileAsync(SPARTAN_BIN, args, {
    cwd: SPARTAN_DIR,
    env: {
      ...process.env,
      RUST_LOG: "info",
      ...(DYLIB_DIR ? { DYLD_LIBRARY_PATH: DYLIB_DIR } : {}),
    },
    timeout: 600_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  return stdout + stderr;
}

function spartan2kKeysExist(): boolean {
  return (
    existsSync(join(SPARTAN_DIR, "keys", "2k_prepare_proving.key")) &&
    existsSync(join(SPARTAN_DIR, "keys", "2k_prepare_verifying.key"))
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Real credential — JWT circuit (Prepare stage)", () => {
  let witnessCalculator: WitnessCalculator;

  beforeAll(async () => {
    witnessCalculator = new WitnessCalculator(ASSETS_DIR);
    await witnessCalculator.init();
  });

  it("parses the bare JWT correctly", () => {
    const cred = Credential.parse(CREDENTIAL_JWT, DISCLOSURES);

    expect(cred.header["alg"]).toBe("ES256");
    expect(cred.header["typ"]).toBe("vc+sd-jwt");

    const payload = cred.payload;
    expect(payload["iss"]).toMatch(/^did:key:/);
    expect(payload["sub"]).toMatch(/^did:key:/);

    // Device binding key (cnf.jwk) must be present and be P-256
    const deviceKey = cred.deviceBindingKey;
    expect(deviceKey).not.toBeNull();
    expect(deviceKey!.kty).toBe("EC");
    expect(deviceKey!.crv).toBe("P-256");
    expect(deviceKey!.x).toBe("VFBwY7pX7dB4D1yaspaTH3InLIKyDBQE98TRW3HHdfo");
    expect(deviceKey!.y).toBe("ZskZ2CgfYjCejCiAMw3ggrQxvvNRM-JNLKVSLDr3cuk");

    // One pending _sd digest, zero attached disclosures
    expect(cred.sdDigests.length).toBe(1);
    expect(cred.claims.length).toBe(0);

    console.log("  iss    :", payload["iss"]);
    console.log("  sub    :", payload["sub"]);
    console.log("  nbf    :", new Date(Number(payload["nbf"]) * 1000).toISOString());
    console.log("  exp    :", new Date(Number(payload["exp"]) * 1000).toISOString());
    console.log("  _sd[0] :", cred.sdDigests[0]);
    console.log("  dev.x  :", deviceKey!.x);
    console.log("  dev.y  :", deviceKey!.y);
  });

  it("fetches issuer public key from JWK Set (jku)", async () => {
    const issuerKey = await fetchIssuerKey(
      "https://issuer-vc.wallet.gov.tw/api/keys",
      "key-1",
    );

    expect(issuerKey.kty).toBe("EC");
    expect(issuerKey.crv).toBe("P-256");
    expect(issuerKey.x).toBeTruthy();
    expect(issuerKey.y).toBeTruthy();

    console.log("  issuer pubKey.x :", issuerKey.x);
    console.log("  issuer pubKey.y :", issuerKey.y);
  }, 15_000);

  it("builds JWT circuit inputs (no disclosures)", async () => {
    const issuerKey = await fetchIssuerKey(
      "https://issuer-vc.wallet.gov.tw/api/keys",
      "key-1",
    );

    const cred = Credential.parse(CREDENTIAL_JWT, DISCLOSURES);

    // No disclosures → no additionalMatches, no decodeFlags
    const inputs = buildJwtCircuitInputs(
      cred,
      issuerKey,
      JWT_2K_PARAMS,
      /* additionalMatches */ [],
      /* decodeFlags       */ [],
      /* claimFormats      */ [],
    );

    // Structural sanity checks
    expect(inputs.message.length).toBe(JWT_2K_PARAMS.maxMessageLength);
    expect(inputs.messageLength).toBeGreaterThan(0);
    expect(inputs.periodIndex).toBeGreaterThan(0);
    // Only the 2 built-in key-extraction patterns ("x":" and "y":") → matchesCount=2
    expect(inputs.matchesCount).toBe(2);

    console.log("  messageLength  :", inputs.messageLength);
    console.log("  periodIndex    :", inputs.periodIndex);
    console.log("  matchesCount   :", inputs.matchesCount);
    console.log("  sig_r          :", inputs.sig_r.toString().slice(0, 20) + "…");
    console.log("  pubKeyX        :", inputs.pubKeyX.toString().slice(0, 20) + "…");
    console.log("  pubKeyY        :", inputs.pubKeyY.toString().slice(0, 20) + "…");
  }, 15_000);

  it("calculates JWT witness — verifies signature and extracts device key", async () => {
    const issuerKey = await fetchIssuerKey(
      "https://issuer-vc.wallet.gov.tw/api/keys",
      "key-1",
    );

    const cred = Credential.parse(CREDENTIAL_JWT, DISCLOSURES);

    // Use default params (1920) — the WASM witness calculator in assets/ is
    // compiled for the default circuit size, not the 2k variant.
    const inputs = buildJwtCircuitInputs(
      cred,
      issuerKey,
      DEFAULT_JWT_PARAMS,
      [],
      [],
      [],
    );

    // This call exercises the full circuit constraint satisfaction.
    // If the issuer signature or key extraction is wrong, it throws.
    const witness = await witnessCalculator.calculateJwtWitness(inputs);

    // w[0] is always 1 in a satisfying assignment
    expect(witness[0]).toBe(1n);

    // JWT circuit output layout (maxMatches=4, maxClaims=2):
    //   w[1] = normalizedClaimValues[0]
    //   w[2] = normalizedClaimValues[1]
    //   w[3] = KeyBindingX
    //   w[4] = KeyBindingY
    const keyBindingX = witness[3];
    const keyBindingY = witness[4];

    // Verify the extracted coordinates match the cnf.jwk in the credential
    const deviceKey = cred.deviceBindingKey!;
    const expectedX = base64urlToBigInt(deviceKey.x);
    const expectedY = base64urlToBigInt(deviceKey.y);

    expect(keyBindingX).toBe(expectedX);
    expect(keyBindingY).toBe(expectedY);

    console.log("  w[0] (valid)      :", witness[0]);
    console.log("  w[1] claimValue[0]:", witness[1]);
    console.log("  w[2] claimValue[1]:", witness[2]);
    console.log("  w[3] KeyBindingX  :", keyBindingX!.toString().slice(0, 20) + "…");
    console.log("  w[4] KeyBindingY  :", keyBindingY!.toString().slice(0, 20) + "…");
    console.log("  KeyBindingX match :", keyBindingX === expectedX);
    console.log("  KeyBindingY match :", keyBindingY === expectedY);
    console.log("  witness length    :", witness.length);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Proof generation + verification (Prepare / JWT circuit only, 2k size)
// ---------------------------------------------------------------------------

describe("Real credential — Spartan2 proof (Prepare circuit, 2k)", () => {
  let witnessCalculator: WitnessCalculator;

  beforeAll(async () => {
    witnessCalculator = new WitnessCalculator(ASSETS_DIR);
    await witnessCalculator.init();
  });

  it("writes 2k JWT inputs from real credential to disk", async () => {
    const issuerKey = await fetchIssuerKey(
      "https://issuer-vc.wallet.gov.tw/api/keys",
      "key-1",
    );
    const cred = Credential.parse(CREDENTIAL_JWT, DISCLOSURES);
    const inputs = buildJwtCircuitInputs(cred, issuerKey, JWT_2K_PARAMS, [], [], []);

    const replacer = (_: string, v: unknown) =>
      typeof v === "bigint" ? v.toString() : v;
    const outDir = join(__dirname, "..", "..", "circom", "inputs", "jwt", "2k");
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, "default.json"), JSON.stringify(inputs, replacer, 2));

    expect(inputs.messageLength).toBe(1920);
    expect(inputs.matchesCount).toBe(2);
    console.log("  Inputs written to circom/inputs/jwt/2k/default.json");
    console.log("  messageLength :", inputs.messageLength);
    console.log("  matchesCount  :", inputs.matchesCount);
  }, 15_000);

  it("proves the Prepare circuit with the real credential (--size 2k)", async () => {
    if (!spartan2kKeysExist()) {
      console.log("  2k keys not found — skipping.");
      console.log("  Run: cd ecdsa-spartan2 && ./target/release/ecdsa-spartan2 prepare setup --size 2k");
      return;
    }

    const t0 = Date.now();
    const out = await runSpartan(["prepare", "prove", "--size", "2k"]);
    const proveMs = Date.now() - t0;

    console.log("  prove :", proveMs, "ms");
    // Log key timing lines from the Rust output
    for (const line of out.split("\n")) {
      if (/witnesscalc|prep_prove|ZK-Spartan prove|Saved/.test(line)) {
        console.log(" ", line.replace(/^.*\] /, "").trim());
      }
    }
  }, 600_000);

  it("verifies the Prepare proof (--size 2k)", async () => {
    if (!spartan2kKeysExist()) {
      console.log("  2k keys not found — skipping.");
      return;
    }

    const t0 = Date.now();
    const out = await runSpartan(["prepare", "verify", "--size", "2k"]);
    const verifyMs = Date.now() - t0;

    expect(out).toContain("Verification successful");
    console.log("  verify :", verifyMs, "ms");
    console.log(" ", out.match(/Verification \w+/)?.[0]);
  }, 120_000);
});
