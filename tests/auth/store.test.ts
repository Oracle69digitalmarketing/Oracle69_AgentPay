/**
 * Replay-store tests. The SAME suite runs against every backend so the
 * durable SQLite implementation and the test-only memory store obey identical
 * single-use semantics. SQLite file cases use real temp files (outside the
 * repo) plus separate store instances sharing one database file.
 */
import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { MemoryReplayStore } from "../../src/auth/store/memory-store.js";
import { SqliteReplayStore } from "../../src/auth/store/sqlite-store.js";
import type { ReplayEntry, ReplayStore } from "../../src/auth/store/types.js";
import { ADDR_A, NOW } from "./helpers.js";

const DIGEST = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function entry(over: Partial<ReplayEntry> = {}): ReplayEntry {
  return {
    nonce: "nonce-001",
    requestId: "req-001",
    recipient: ADDR_A,
    amountWei: "400000000000000000",
    expiresAt: NOW + 3600,
    consumedAt: NOW,
    policyDigest: DIGEST,
    ...over,
  };
}

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function tempDbPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "agentpay-m2-"));
  tempDirs.push(dir);
  return join(dir, "replay.db");
}

interface Backend {
  name: string;
  open: () => ReplayStore;
}

const memoryBackend: Backend = {
  name: "memory",
  open: () => new MemoryReplayStore(),
};
const sqliteMemoryBackend: Backend = {
  name: "sqlite/:memory:",
  open: () => new SqliteReplayStore(":memory:"),
};

describe.each([
  { backend: () => memoryBackend.open(), label: "memory" },
  { backend: () => sqliteMemoryBackend.open(), label: "sqlite/:memory:" },
])("replay store ($label)", ({ backend }) => {
  it("first valid claim succeeds", () => {
    const s = backend();
    try {
      expect(s.claim(entry())).toEqual({ ok: true });
    } finally {
      s.close();
    }
  });

  it("reuse of a consumed nonce is rejected", () => {
    const s = backend();
    try {
      expect(s.claim(entry()).ok).toBe(true);
      expect(s.claim(entry({ requestId: "req-002" }))).toEqual({ ok: false, reused: "nonce" });
      expect(s.isConsumedByNonce("nonce-001")).toBe(true);
    } finally {
      s.close();
    }
  });

  it("reuse of a consumed requestId with a fresh nonce is rejected", () => {
    const s = backend();
    try {
      expect(s.claim(entry()).ok).toBe(true);
      expect(s.claim(entry({ nonce: "nonce-002" }))).toEqual({ ok: false, reused: "requestId" });
      expect(s.isConsumedByRequestId("req-001")).toBe(true);
    } finally {
      s.close();
    }
  });

  it("invalid state reads on fresh identifiers are negative", () => {
    const s = backend();
    try {
      expect(s.isConsumedByNonce("nope")).toBe(false);
      expect(s.isConsumedByRequestId("nope")).toBe(false);
    } finally {
      s.close();
    }
  });
});

describe("sqlite file backend (durable)", () => {
  it("consumed identifiers remain blocked after close and reopen", () => {
    const path = tempDbPath();
    const a = new SqliteReplayStore(path);
    expect(a.claim(entry()).ok).toBe(true);
    a.close();

    const b = new SqliteReplayStore(path);
    try {
      expect(b.claim(entry({ requestId: "req-002" }))).toEqual({ ok: false, reused: "nonce" });
      expect(b.claim(entry({ nonce: "nonce-002" }))).toEqual({ ok: false, reused: "requestId" });
    } finally {
      b.close();
    }
  });

  it("concurrent attempts on the same nonce yield exactly one success (separate instances)", async () => {
    const path = tempDbPath();
    const attempts = Array.from({ length: 12 }, (_, i) =>
      (async () => {
        const s = new SqliteReplayStore(path);
        try {
          await Promise.resolve(); // force distinct async interleaving
          return s.claim(entry({ requestId: `req-c-${i}` }));
        } finally {
          s.close();
        }
      })(),
    );
    const results = await Promise.all(attempts);
    expect(results.filter((r) => r.ok).length).toBe(1);
    expect(results.filter((r) => !r.ok && r.reused === "nonce").length).toBe(11);
  });

  it("concurrent attempts on the same requestId yield exactly one success (separate instances)", async () => {
    const path = tempDbPath();
    const attempts = Array.from({ length: 12 }, (_, i) =>
      (async () => {
        const s = new SqliteReplayStore(path);
        try {
          await Promise.resolve();
          return s.claim(entry({ nonce: `nonce-c-${i}` }));
        } finally {
          s.close();
        }
      })(),
    );
    const results = await Promise.all(attempts);
    expect(results.filter((r) => r.ok).length).toBe(1);
    expect(results.filter((r) => !r.ok && r.reused === "requestId").length).toBe(11);
  });

  it("independent instances sharing one database cannot both authorize the same identifiers", () => {
    const path = tempDbPath();
    const a = new SqliteReplayStore(path);
    const b = new SqliteReplayStore(path);
    try {
      expect(a.claim(entry()).ok).toBe(true);
      expect(b.claim(entry({ requestId: "req-other" }))).toEqual({ ok: false, reused: "nonce" });
    } finally {
      a.close();
      b.close();
    }
  });

  it("use after close throws (fail closed at the call site)", () => {
    const s = new SqliteReplayStore(":memory:");
    s.close();
    expect(() => s.claim(entry())).toThrow();
  });

  it("unusable database path fails closed at construction", () => {
    expect(() => new SqliteReplayStore("/nonexistent-dir-xyz/replay.db")).toThrow();
    expect(() => new SqliteReplayStore("")).toThrow();
  });
});

/**
 * Genuine cross-process contention: separate OS processes, independent
 * connections, one local database file. A start barrier (go-file) forces the
 * claim windows to overlap instead of relying on spawn timing.
 *
 * Setup compiles the real store sources to a temp dir (outside the repo) and
 * symlinks node_modules for ESM resolution. This proves the SQLite locking +
 * UNIQUE constraints — not the event loop — enforce single-use.
 *
 * Explicitly NOT claimed: safety over NFS or arbitrary shared filesystems.
 */
describe("sqlite cross-process contention (separate OS processes)", () => {
  const execFileAsync = promisify(execFile);
  let root = "";
  let childScript = "";
  let goCounter = 0;

  const THIS_FILE = fileURLToPath(import.meta.url);
  const REPO_ROOT = resolve(dirname(THIS_FILE), "..", "..");

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "agentpay-xproc-"));
    // Own lifecycle (afterAll below): the shared afterEach wipes per-test
    // tempDirs, which would otherwise delete this root between tests.
    symlinkSync(join(REPO_ROOT, "node_modules"), join(root, "node_modules"));
    const build = join(root, "build");
    // Compile ONLY the store sources (plus their local types import).
    execFileSync(join(REPO_ROOT, "node_modules", ".bin", "tsc"), [
      join(REPO_ROOT, "src", "auth", "store", "sqlite-store.ts"),
      join(REPO_ROOT, "src", "auth", "store", "types.ts"),
      "--outDir", build,
      "--rootDir", join(REPO_ROOT, "src"),
      "--module", "nodenext",
      "--target", "es2022",
      "--moduleResolution", "nodenext",
      "--skipLibCheck",
      "--declaration", "false",
      "--sourceMap", "false",
    ]);
    if (!existsSync(join(build, "auth", "store", "sqlite-store.js"))) {
      throw new Error("cross-process setup failed: compiled store missing");
    }
    childScript = join(root, "claim-child.mjs");
    writeFileSync(
      childScript,
      `import fs from "node:fs";\n` +
        `import { SqliteReplayStore } from "./build/auth/store/sqlite-store.js";\n` +
        `const [dbPath, goFile, entryJson] = process.argv.slice(2);\n` +
        `const entry = JSON.parse(entryJson);\n` +
        `const start = Date.now();\n` +
        `while (!fs.existsSync(goFile)) {\n` +
        `  if (Date.now() - start > 15000) { console.log(JSON.stringify({ ok: false, error: "barrier-timeout" })); process.exit(2); }\n` +
        `  await new Promise((r) => setTimeout(r, 5));\n` +
        `}\n` +
        `let store;\n` +
        `try {\n` +
        `  store = new SqliteReplayStore(dbPath);\n` +
        `  console.log(JSON.stringify(store.claim(entry)));\n` +
        `} catch (e) {\n` +
        `  console.log(JSON.stringify({ ok: false, error: String((e && e.message) || e) }));\n` +
        `  process.exitCode = 1;\n` +
        `} finally {\n` +
        `  try { store && store.close(); } catch {}\n` +
        `}\n`,
    );
  }, 120_000);

  afterAll(() => {
    if (root !== "") rmSync(root, { recursive: true, force: true });
  });

  async function raceClaims(dbPath: string, entries: ReplayEntry[]): Promise<unknown[]> {
    const goFile = join(root, `go-${goCounter++}`);
    const runs = entries.map((e) =>
      execFileAsync(process.execPath, [childScript, dbPath, goFile, JSON.stringify(e)], {
        timeout: 30_000,
      }).then(
        ({ stdout }) => JSON.parse(stdout.trim().split("\n").at(-1) as string) as unknown,
        (err: unknown) => {
          const out = (err as { stdout?: string })?.stdout?.trim().split("\n").at(-1);
          try {
            return out ? (JSON.parse(out) as unknown) : { ok: false, error: String(err) };
          } catch {
            return { ok: false, error: String(err) };
          }
        },
      ),
    );
    // Let every child reach the barrier before releasing them together.
    await new Promise((r) => setTimeout(r, 800));
    writeFileSync(goFile, "go");
    return Promise.all(runs);
  }

  it("competing processes on the same nonce yield exactly one success", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agentpay-xpn-"));
    tempDirs.push(dir);
    const dbPath = join(dir, "replay.db");
    // Initialize schema from the parent (also proves concurrent init is safe
    // when children open the same file moments later).
    new SqliteReplayStore(dbPath).close();
    const results = await raceClaims(
      dbPath,
      Array.from({ length: 6 }, (_, i) => entry({ requestId: `req-xp-${i}` })),
    );
    const ok = results.filter((r) => (r as { ok?: boolean }).ok === true);
    const nonceLosses = results.filter(
      (r) => (r as { reused?: string }).reused === "nonce",
    );
    expect(ok.length, `expected exactly 1 winner, got: ${JSON.stringify(results)}`).toBe(1);
    expect(nonceLosses.length, `expected 5 nonce-losses, got: ${JSON.stringify(results)}`).toBe(5);
  }, 120_000);

  it("competing processes on the same requestId yield exactly one success", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agentpay-xpr-"));
    tempDirs.push(dir);
    const dbPath = join(dir, "replay.db");
    new SqliteReplayStore(dbPath).close();
    const results = await raceClaims(
      dbPath,
      Array.from({ length: 6 }, (_, i) => entry({ nonce: `nonce-xpr-${i}` })),
    );
    const ok = results.filter((r) => (r as { ok?: boolean }).ok === true);
    const reqLosses = results.filter(
      (r) => (r as { reused?: string }).reused === "requestId",
    );
    expect(ok.length, `expected exactly 1 winner, got: ${JSON.stringify(results)}`).toBe(1);
    expect(reqLosses.length, `expected 5 request-losses, got: ${JSON.stringify(results)}`).toBe(5);
  }, 120_000);
});
