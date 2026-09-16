import { describe, it, expect } from "vitest";
import { mintNonce } from "../nonce.js";

describe("mintNonce — the shared fence-nonce minter", () => {
  it("returns 32 hex chars (128-bit CSPRNG token)", () => {
    expect(mintNonce()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("returns a fresh value on each call (no reuse)", () => {
    expect(mintNonce()).not.toBe(mintNonce());
  });
});
