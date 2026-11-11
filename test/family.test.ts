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

test("anything else is 'high-entropy'", () => {
	assert.equal(familyOf(OPAQUE), "high-entropy");
	assert.equal(familyOf(hex(40)), "high-entropy");
});

test("FAMILIES lists the shape classes", () => {
	assert.deepEqual([...FAMILIES].sort(), ["high-entropy", "identifier", "prefixed-id", "uuid"]);
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
