//
// The fence boundary token is a single fresh CSPRNG value per fenced blob. Its only
// job is to be UNGUESSABLE by the content's author: the source never sees it, so
// content inside the fence cannot forge a matching closing delimiter. It is NOT a
// hash chain — each call is an independent throwaway, which is exactly what every
// production fence caller used in practice (one nonce per clean/fetch/transcript).
//
// 16 bytes = 128 bits, rendered as 32 hex chars: long enough to be unforgeable,
// short enough to read inside a <untrusted-{nonce}> tag.

import { randomBytes } from "node:crypto";

/**
 * Mint a fresh fence nonce: a CSPRNG 128-bit token as 32 hex chars.
 *
 * Use this as the `nonce` argument to fenceUntrusted/fenceInput. Each call returns
 * an independent random value — the whole point is that the untrusted source never
 * saw it and cannot predict it, so it cannot forge the fence boundary.
 */
export function mintNonce(): string {
  return randomBytes(16).toString("hex");
}
