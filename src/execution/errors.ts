/**
 * Error sanitization — Oracle69 AgentPay M3 (P0 remediation).
 *
 * PROBLEM: RPC client errors (viem `TimeoutError`, `HttpRequestError`, and
 * siblings) embed the full JSON-RPC request body — including signed raw
 * transaction bytes — inside `err.message` via `metaMessages`. Persisting or
 * returning `err.message` would leak broadcastable signed transactions into
 * SQLite (`last_error`) and API decisions.
 *
 * RULES:
 * 1. Classify on the RAW error (name/message signals), because sanitizing
 *    first could destroy the timeout-vs-rejection distinction. A sanitized
 *    message must NEVER flip an ambiguous outcome to "safe to retry".
 * 2. Persist/return ONLY the sanitized form: safe category + redacted detail.
 * 3. Redaction removes (a) every 0x-hex run of 100+ chars in any casing
 *    (signed transactions ~220+, authorization signatures = 130; plain
 *    addresses (40) and tx hashes (64) are preserved for diagnostics),
 *    and (b) any `Request body:` segment through end-of-line, tolerating
 *    whitespace/capitalization/format variations, while KEEPING surrounding
 *    diagnostic text on other lines.
 * 4. Output is bounded (300 chars). If nothing safe remains, keep only the
 *    category ("unavailable").
 */
import { isAmbiguousSendError } from "./chain.js";
export type SafeErrorCategory =
  | "RPC_TIMEOUT"
  | "RPC_REJECTED"
  | "RPC_UNAVAILABLE"
  | "HASH_MISMATCH"
  | "PREPARATION_FAILED"
  | "SIGNING_FAILED";

export interface SafeError {
  category: SafeErrorCategory;
  /** Redacted, bounded diagnostic. Safe to persist and return. */
  detail: string;
}

const LONG_HEX = /0x[0-9a-fA-F]{100,}/g;
const MAX_DETAIL = 300;

function errorName(err: unknown): string {
  const name = err instanceof Error ? err.name : "";
  return /^[A-Za-z]+Error$/.test(name) ? name : "Error";
}

function rawMessage(err: unknown): string {
  if (err === null || err === undefined) return "unavailable";
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return "unavailable";
  }
}

/**
 * Remove `Request body: <value>` segments (any casing/whitespace), consuming
 * exactly one JSON-ish value so trailing diagnostics on the same line are
 * preserved. Unbalanced input fails safe: the remainder of the line is cut.
 */
function stripRequestBodies(text: string): string {
  const head = /request\s*body\s*:/gi;
  let out = "";
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = head.exec(text)) !== null) {
    out += text.slice(last, m.index) + "Request body: [redacted]";
    let i = m.index + m[0].length;
    while (i < text.length && /\s/.test(text[i] as string)) i++;
    const open = text[i];
    if (open === "{" || open === "[") {
      const close = open === "{" ? "}" : "]";
      let depth = 0;
      let inStr = false;
      let esc = false;
      while (i < text.length) {
        const ch = text[i] as string;
        if (inStr) {
          if (esc) esc = false;
          else if (ch === "\\") esc = true;
          else if (ch === '"') inStr = false;
        } else if (ch === '"') {
          inStr = true;
        } else if (ch === open) {
          depth++;
        } else if (ch === close) {
          depth--;
          if (depth === 0) {
            i++;
            break;
          }
        }
        i++;
      }
    } else if (open === '"') {
      i++;
      while (i < text.length && text[i] !== "\n") {
        if (text[i] === "\\") i++;
        else if (text[i] === '"') {
          i++;
          break;
        }
        i++;
      }
    } else {
      while (i < text.length && text[i] !== "\n" && !/\s/.test(text[i] as string)) i++;
    }
    last = i;
    head.lastIndex = i;
  }
  return out + text.slice(last);
}

/** Strip sensitive payloads; preserve surrounding diagnostics. */
export function sanitizeDetail(err: unknown): string {
  let text = rawMessage(err);
  text = text.replace(LONG_HEX, "[redacted-hex]");
  text = stripRequestBodies(text);
  // Second pass in case excision exposed newly adjacent long runs.
  text = text.replace(LONG_HEX, "[redacted-hex]");
  text = text.replace(/\s+/g, " ").trim().slice(0, MAX_DETAIL);
  return text.length > 0 ? text : "unavailable";
}

/** Classify on RAW signals; never derive retry-safety from sanitized text. */
export function classifySendError(err: unknown): { ambiguous: boolean; category: SafeErrorCategory } {
  return isAmbiguousSendError(err)
    ? { ambiguous: true, category: "RPC_TIMEOUT" }
    : { ambiguous: false, category: "RPC_REJECTED" };
}

/** Full pipeline for RPC failures: classify raw, then sanitize for exposure. */
export function safeSendError(err: unknown): { ambiguous: boolean; error: SafeError } {
  const { ambiguous, category } = classifySendError(err);
  return { ambiguous, error: { category, detail: `${errorName(err)}: ${sanitizeDetail(err)}` } };
}

/** For non-send external failures (chain checks, receipt polling). */
export function safeExternalError(category: SafeErrorCategory, err: unknown): SafeError {
  return { category, detail: `${errorName(err)}: ${sanitizeDetail(err)}` };
}
