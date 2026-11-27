// Contract for pi-redact#6: every `pi-redact` entry says which family each
// new value belongs to, and never the value or any piece of it. Fake keys are
// built at run time so no key-shaped string sits in the repo.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createRedactor } from "../extensions/pi-redact.ts";
import { findVendorKeys } from "../src/detect.ts";
import { FAMILIES, familyOf } from "../src/family.ts";

const ABC = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789";
let seed = 0xfa417;
const body = (n: number): string => {
	let s = "";
	for (let i = 0; i < n; i++) {
		seed = (seed * 1103515245 + 12345) >>> 0;
		s += ABC[seed % ABC.length];
	}
	return `${s}Q7z`;
};
const hex = (n: number): string => {
	let s = "";
	for (let i = 0; i < n; i++) {
		seed = (seed * 1103515245 + 12345) >>> 0;
		s += "0123456789abcdef"[seed % 16];
	}
	return s;
};

const GATEWAY = `v${"ck_"}${body(53)}`;
const LINEAR = `lin${"_api_"}${body(37)}`;
const GITHUB = `gh${"p_"}${body(33)}`;
const UUID_V4 = `${hex(8)}-${hex(4)}-4${hex(3)}-a${hex(3)}-${hex(12)}`;
const UUID_V7 = `01a1c705-${hex(4)}-7${hex(3)}-b${hex(3)}-${hex(12)}`;
const SNAPSHOT = `snap_${body(21)}`;
const AGENT = `agent_01${body(20)}`;
const GO_CONST = `Model${body(14)}Sonnet4${body(8)}`;
const OPAQUE = `${body(12)}+/${body(14)}==`;

/** True when `text` contains any run of `n` characters taken from `value`. */
function leaks(text: string, value: string, n = 6): boolean {
	for (let i = 0; i + n <= value.length; i++) if (text.includes(value.slice(i, i + n))) return true;
	return false;
}

function harness() {
	const handlers = new Map<string, ((event: any, ctx: any) => any)[]>();
	const entries: { type: string; data: any }[] = [];
	const ctx = {
		hasUI: true,
		ui: { notify: () => {}, setStatus: () => {}, theme: { fg: (_c: string, s: string) => s } },
		sessionManager: { getBranch: () => [], getHeader: () => ({ type: "session", id: "session-family" }) },
	};
	const pi = {
		on: (name: string, h: (event: any, ctx: any) => any) => {
			handlers.set(name, [...(handlers.get(name) ?? []), h]);
			return () => {};
		},
		registerCommand: () => {},
		appendEntry: (type: string, data: any) => entries.push({ type, data }),
	};
	createRedactor(pi as any, { options: {}, machineKey: "test-machine-key" });
	const fire = (name: string, event: any) => {
		let result: any;
		for (const h of handlers.get(name) ?? []) result = h(event, ctx);
		return result;
	};
	const logged = () => entries.filter((e) => e.type === "pi-redact").map((e) => e.data);
	return { fire, entries, logged };
}

test("a vendor key gets the family findVendorKeys reports", () => {
	for (const key of [GATEWAY, LINEAR, GITHUB]) {
		const hit = findVendorKeys(key)[0];
		assert.ok(hit, "the fixture is a vendor shape");
		assert.equal(familyOf(key), hit.family);
	}
});

test("a UUID is 'uuid', in either case", () => {
	assert.equal(familyOf(UUID_V4), "uuid");
	assert.equal(familyOf(UUID_V7), "uuid");
	assert.equal(familyOf(UUID_V7.toUpperCase()), "uuid");
});

test("a lowercase prefix, an underscore and an opaque tail is 'prefixed-id'", () => {
	assert.equal(familyOf(SNAPSHOT), "prefixed-id");
	assert.equal(familyOf(AGENT), "prefixed-id");
});

test("a vendor shape wins over 'prefixed-id'", () => {
	assert.notEqual(familyOf(LINEAR), "prefixed-id");
	assert.notEqual(familyOf(GITHUB), "prefixed-id");
});

test("mixed-case letters and digits with no separator is 'identifier'", () => {
	assert.equal(familyOf(GO_CONST), "identifier");
});

test("a JWT, whole or cut after its payload, is 'jwt'", () => {
	const jwt = `ey${"J"}${body(30)}.ey${"J"}${body(60)}`;
	assert.equal(familyOf(`${jwt}.${body(40)}`), "jwt");
	assert.equal(familyOf(jwt), "jwt");
});

test("anything else is 'high-entropy'", () => {
	assert.equal(familyOf(OPAQUE), "high-entropy");
	assert.equal(familyOf(hex(40)), "high-entropy");
});

test("FAMILIES lists the shape classes", () => {
	assert.deepEqual([...FAMILIES].sort(), ["high-entropy", "identifier", "jwt", "password-key", "prefixed-id", "uuid"]);
});

test("a family name never carries a piece of the value", () => {
	for (const value of [UUID_V4, UUID_V7, SNAPSHOT, AGENT, GO_CONST, OPAQUE]) {
		assert.ok(!leaks(familyOf(value), value, 4), `family leaks a piece of ${value.slice(0, 4)}...`);
	}
	// A vendor family may name the public prefix; it must not reach the random part.
	for (const [key, prefix] of [[GATEWAY, 4], [LINEAR, 8], [GITHUB, 4]] as const) {
		assert.ok(!leaks(familyOf(key), key.slice(prefix), 4), "vendor family leaks a piece of the key body");
	}
});

test("an entry counts its new values by family", () => {
	const h = harness();
	const r = h.fire("input", { type: "input", text: `use ${LINEAR} and ${GITHUB} please`, source: "interactive" });
	assert.equal(r.action, "transform");
	const [entry] = h.logged();
	assert.ok(entry, "one entry for the prompt");
	assert.equal(entry.values, 2);
	assert.equal(entry.vendor, 2);
	assert.deepEqual(entry.families, { [familyOf(LINEAR)]: 1, [familyOf(GITHUB)]: 1 });
});

test("two values of one family are one key with a count of two", () => {
	const h = harness();
	const other = `lin${"_api_"}${body(37)}`;
	h.fire("input", { type: "input", text: `use ${LINEAR} then ${other}`, source: "interactive" });
	const [entry] = h.logged();
	assert.ok(entry);
	assert.deepEqual(entry.families, { [familyOf(LINEAR)]: 2 });
});

test("family counts add up to `values` on every entry, and no entry carries a value", () => {
	const h = harness();
	h.fire("input", { type: "input", text: `use ${GATEWAY} please`, source: "interactive" });
	const call = { type: "tool_call", toolCallId: "c1", toolName: "bash", input: { command: "cat .env" } };
	h.fire("tool_call", call);
	const output = `K=${LINEAR}\nG=${GITHUB}\nH=${GATEWAY}`;
	h.fire("tool_result", { type: "tool_result", toolCallId: "c1", toolName: "bash", input: call.input, content: [{ type: "text", text: output }], isError: false, details: { full: output } });
	const logged = h.logged();
	assert.equal(logged.length, 2, "one entry per channel that brought a new value");
	for (const entry of logged) {
		const total = Object.values(entry.families as Record<string, number>).reduce((a, b) => a + b, 0);
		assert.equal(total, entry.values);
	}
	const text = JSON.stringify(h.entries);
	for (const [key, prefix] of [[GATEWAY, 4], [LINEAR, 8], [GITHUB, 4]] as const) {
		assert.ok(!leaks(text, key.slice(prefix), 6), "an entry carries a piece of a key");
	}
});

// `password-key`: the detector took the value for the name or flag in front
// of it. The vault is shared by every harness in this file, so each case
// below uses values no other case has seen.
const human = (): string => `Summer${hex(2)}${body(2)}!`;
const dashed = (): string => `${body(16)}-${body(16)}`;
const camel = (): string => `Model${body(14)}Sonnet4${body(8)}`;
const prompt = (text: string) => {
	const h = harness();
	const r = h.fire("input", { type: "input", text, source: "interactive" });
	return { ...h, result: r };
};

test("a value under a password-like key is 'password-key', whatever its shape", () => {
	const shapes = [human(), dashed(), `${hex(8)}-${hex(4)}-7${hex(3)}-b${hex(3)}-${hex(12)}`, camel()];
	const lines = [
		(v: string) => `password=${v}`,
		(v: string) => `{"secret": "${v}"}`,
		(v: string) => `DB_PASS=${v}`,
		(v: string) => `client_secret: ${v}`,
	];
	for (const [i, value] of shapes.entries()) {
		assert.notEqual(familyOf(value), "password-key", "the shape alone never gives this family");
		const { result, logged } = prompt(lines[i]!(value));
		assert.equal(result.action, "transform");
		assert.ok(!result.text.includes(value), "the value is hidden");
		assert.deepEqual(logged(), [{ source: "prompt:interactive", values: 1, vendor: 0, families: { "password-key": 1 } }]);
	}
});

test("a password flag and a password column count as 'password-key' too", () => {
	for (const line of [(v: string) => `tool --password ${v} --verbose`, (v: string) => `INSERT INTO users (name, password) VALUES ('bob', '${v}');`]) {
		const value = human();
		const { result, logged } = prompt(line(value));
		assert.ok(!result.text.includes(value), "the value is hidden");
		assert.deepEqual(logged()[0]?.families, { "password-key": 1 });
	}
});

test("the same shapes with no password-like key keep their families", () => {
	const { logged } = prompt(`see ${dashed()} and ${camel()} in the log`);
	assert.deepEqual(logged()[0]?.families, { "high-entropy": 1, identifier: 1 });
	// A name the detector judges by entropy (`token=`) is not a password-like key.
	assert.deepEqual(prompt(`token=${camel()}`).logged()[0]?.families, { identifier: 1 });
	assert.deepEqual(prompt(`token=${dashed()}`).logged()[0]?.families, { "high-entropy": 1 });
});

test("a vendor key under a password-like key keeps its vendor family", () => {
	const key = `gh${"p_"}${body(33)}`;
	const { logged } = prompt(`password=${key}`);
	const [entry] = logged();
	assert.ok(entry);
	assert.equal(entry.vendor, 1);
	assert.deepEqual(entry.families, { [familyOf(key)]: 1 });
	assert.equal(familyOf(key, true), familyOf(key));
});

test("'password-key' sits beside the other families and the counts still add up", () => {
	const pw = human();
	const key = `lin${"_api_"}${body(37)}`;
	const { logged } = prompt(`password=${pw}\nLINEAR=${key}\nsee ${dashed()} in the log`);
	const [entry] = logged();
	assert.ok(entry);
	assert.deepEqual(entry.families, { "password-key": 1, [familyOf(key)]: 1, "high-entropy": 1 });
	assert.equal(entry.values, 3);
	assert.equal(entry.vendor, 1);
});

test("a 'password-key' entry carries no piece of the value, on any channel", () => {
	const h = harness();
	const typed = human();
	const printed = human();
	const quoted = dashed();
	h.fire("input", { type: "input", text: `log in with password=${typed}`, source: "interactive" });
	const call = { type: "tool_call", toolCallId: "p1", toolName: "bash", input: { command: "cat config.json .env" } };
	h.fire("tool_call", call);
	const output = `{"secret": "${quoted}"}\nDB_PASSWORD=${printed}`;
	h.fire("tool_result", { type: "tool_result", toolCallId: "p1", toolName: "bash", input: call.input, content: [{ type: "text", text: output }], isError: false, details: { full: output } });
	const logged = h.logged();
	assert.deepEqual(logged.map((e) => e.families), [{ "password-key": 1 }, { "password-key": 2 }]);
	for (const entry of logged) assert.deepEqual(Object.keys(entry).sort(), ["families", "source", "values", "vendor"]);
	const text = JSON.stringify(h.entries);
	for (const value of [typed, printed, quoted]) {
		assert.ok(!leaks(text, value, 4), "an entry carries a piece of a password");
		assert.ok(!leaks("password-key", value, 4), "the family name carries a piece of a password");
	}
});
