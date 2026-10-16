// Placeholders are keyed, not random: a fresh process (a /reload, a restart,
// a resume) must mint the same placeholder for the same value, or the history
// it sends changes and the prompt cache rewrites the whole context. Fake keys
// are built at run time so no key-shaped string sits in the repo.
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createRedactor, loadMachineKey } from "../extensions/pi-redact.ts";

type Detector = typeof import("../src/detect.ts");
const fresh = async (q: string): Promise<Detector> => import(new URL(`../src/detect.ts?${q}`, import.meta.url).href);

const ABC = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789";
let seed = 0x7a95;
const body = (n: number): string => {
	let s = "";
	for (let i = 0; i < n; i++) {
		seed = (seed * 1103515245 + 12345) >>> 0;
		s += ABC[seed % ABC.length];
	}
	return `${s}Q7z`;
};
const GATEWAY = `v${"ck_"}${body(53)}`;
const LINEAR = `lin${"_api_"}${body(37)}`;
const TAGS = /\[REDACTED-SECRET-[0-9a-f]{8}\]/g;
const KEY_A = new Uint8Array(32).fill(7);
const KEY_B = new Uint8Array(32).fill(9);
const TEXT = `export AI_GATEWAY_API_KEY=${GATEWAY}\nlinear token: ${LINEAR}`;

test("two fresh detectors with the same key mint the same placeholders", async () => {
	const one = await fresh("one");
	const two = await fresh("two");
	one.setTagKey(KEY_A);
	two.setTagKey(KEY_A);
	const a = one.scrubSecrets(TEXT, one.makeConfig({}));
	const b = two.scrubSecrets(TEXT, two.makeConfig({}));
	assert.equal(a.match(TAGS)?.length, 2);
	assert.equal(b, a, "a reloaded detector changed the placeholders: the cache prefix breaks");
	assert.equal(one.restore(a), TEXT);
	assert.equal(two.restore(b), TEXT);
});

test("placeholders depend on the key, not only on the value", async () => {
	const one = await fresh("key-a");
	const other = await fresh("key-b");
	one.setTagKey(KEY_A);
	other.setTagKey(KEY_B);
	const a = one.scrubSecrets(TEXT, one.makeConfig({}));
	const b = other.scrubSecrets(TEXT, other.makeConfig({}));
	assert.notEqual(b, a, "tags link sessions that use different keys");
	const bare = createHash("sha256").update(GATEWAY).digest("hex").slice(0, 8);
	assert.ok(!a.includes(bare), "the tag is the bare hash of the value: a guess can be confirmed");
});

test("a tag is the HMAC-SHA256 of kind, attempt and value", async () => {
	const d = await fresh("hmac");
	d.setTagKey(KEY_A);
	const mac = createHmac("sha256", KEY_A).update(`SECRET\u00000\u0000${GATEWAY}`).digest("hex");
	assert.equal(d.mint("SECRET", GATEWAY), `[REDACTED-SECRET-${mac.slice(0, 8)}]`);
});

test("a new key starts a new vault", async () => {
	const d = await fresh("rekey");
	d.setTagKey(KEY_A);
	const tag = d.mint("SECRET", GATEWAY);
	assert.equal(d.restore(tag), GATEWAY);
	d.setTagKey(KEY_B);
	assert.equal(d.restore(tag), tag, "a tag from the old key still restores");
	assert.notEqual(d.mint("SECRET", GATEWAY), tag);
	d.setTagKey(KEY_A);
	assert.equal(d.mint("SECRET", GATEWAY), tag, "the same key mints the same tag again");
});

type Handler = (event: any, ctx: any) => any;

function harness(header: any, init: { machineKey?: string; keyPath?: string }) {
	const handlers = new Map<string, Handler[]>();
	const session = { header };
	const ctx = {
		hasUI: false,
		ui: { notify: () => {}, setStatus: () => {}, theme: { fg: (_c: string, s: string) => s } },
		sessionManager: { getBranch: () => [], getHeader: () => session.header },
	};
	const pi = {
		on: (name: string, h: Handler) => {
			handlers.set(name, [...(handlers.get(name) ?? []), h]);
			return () => {};
		},
		registerCommand: () => {},
		appendEntry: () => {},
	};
	createRedactor(pi as any, init);
	const fire = (name: string, event: any) => {
		let result: any;
		for (const h of handlers.get(name) ?? []) result = h(event, ctx);
		return result;
	};
	const start = (next: any) => {
		session.header = next;
		fire("session_start", { type: "session_start" });
	};
	// Fresh message objects each request, as pi builds them.
	const request = (): string => {
		const messages = [
			{ role: "user", content: [{ type: "text", text: `old paste ${LINEAR}` }], timestamp: 1 },
			{ role: "bashExecution", command: "cat .env", output: `KEY=${GATEWAY}`, exitCode: 0, cancelled: false, truncated: false, timestamp: 2 },
		];
		return JSON.stringify(fire("context", { type: "context", messages }).messages);
	};
	return { start, request };
}

test("a session sends the same history after its vault is lost", () => {
	const h = harness({ type: "session", id: "session-a" }, { machineKey: "machine" });
	h.start({ type: "session", id: "session-a" });
	const first = h.request();
	assert.ok(!first.includes(GATEWAY) && !first.includes(LINEAR));
	h.start({ type: "session", id: "session-b" });
	const other = h.request();
	assert.notEqual(other, first, "two sessions share placeholders: they can be linked");
	h.start({ type: "session", id: "session-a" });
	assert.equal(h.request(), first, "the resumed session re-minted different placeholders");
});

test("a fork keeps its root's placeholders", () => {
	const dir = mkdtempSync(join(tmpdir(), "pi-redact-"));
	const root = join(dir, "root.jsonl");
	const middle = join(dir, "middle.jsonl");
	writeFileSync(root, `${JSON.stringify({ type: "session", id: "session-root" })}\n`);
	writeFileSync(middle, `${JSON.stringify({ type: "session", id: "session-middle", parentSession: root })}\n`);
	const h = harness(null, { machineKey: "machine" });
	h.start({ type: "session", id: "session-root" });
	const parent = h.request();
	h.start({ type: "session", id: "unrelated" });
	h.request();
	h.start({ type: "session", id: "session-fork", parentSession: middle });
	assert.equal(h.request(), parent);
});

test("the machine key is created once, private, and reused", () => {
	const dir = mkdtempSync(join(tmpdir(), "pi-redact-"));
	const keyPath = join(dir, "pi-redact.key");
	harness(null, { keyPath }).start({ type: "session", id: "session-a" });
	const key = readFileSync(keyPath, "utf8");
	assert.match(key, /^[0-9a-f]{64}\n$/);
	assert.equal(statSync(keyPath).mode & 0o777, 0o600);
	harness(null, { keyPath }).start({ type: "session", id: "session-a" });
	assert.equal(readFileSync(keyPath, "utf8"), key, "a second process replaced the key");
	assert.equal(loadMachineKey(keyPath), key.trim());
});
