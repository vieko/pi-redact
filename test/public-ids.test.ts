// pi-redact#6 (narrow slice): UUIDs and Vercel Sandbox snapshot and agent ids
// are public handles, even on a line that also holds a vendor key. Values
// beside a key name stay hidden. Ids are built at run time from the high bits
// of the generator (its low bits repeat, and a repeat of a hidden value is
// rightly hidden again).
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildConfig } from "../extensions/pi-redact.ts";
import { scrubSecrets } from "../src/detect.ts";

let seed = 0x5eed7;
const pick = (abc: string, n: number): string => {
	let s = "";
	for (let i = 0; i < n; i++) {
		seed = (seed * 1103515245 + 12345) >>> 0;
		s += abc[(seed >>> 16) % abc.length];
	}
	return s;
};
const hex = (n: number) => pick("0123456789abcdef", n);
const alnum = (n: number) => `${pick("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789", n)}Q7z`;

const v7 = () => `01a1${hex(4)}-${hex(4)}-7${hex(3)}-${pick("89ab", 1)}${hex(3)}-${hex(12)}`;
const v4 = () => `${hex(8)}-${hex(4)}-4${hex(3)}-${pick("89ab", 1)}${hex(3)}-${hex(12)}`;
const cfg = buildConfig({});
const hidden = (text: string, value: string) => !scrubSecrets(text, cfg).includes(value);

test("a bare UUIDv7 in prose is kept", () => {
	for (let i = 0; i < 5; i++) {
		const id = v7();
		assert.equal(scrubSecrets(`rex session ${id} opened`, cfg), `rex session ${id} opened`);
		assert.equal(scrubSecrets(`"sessionId": "${id}"`, cfg), `"sessionId": "${id}"`);
	}
});

test("an upper-case UUIDv7 is kept too", () => {
	const id = v7().toUpperCase();
	assert.equal(scrubSecrets(`id ${id}`, cfg), `id ${id}`);
});

test("a UUIDv7 beside a key name is still hidden", () => {
	for (const name of ["api_key=", "SECRET="]) {
		const id = v7();
		assert.ok(hidden(`${name}${id}`, id), `${name} value leaked`);
	}
});

test("snapshot and agent ids are kept", () => {
	const snap = `snap_${alnum(21)}`;
	const agent = `agent_01${alnum(20)}`;
	assert.equal(scrubSecrets(`snapshot ${snap} built`, cfg), `snapshot ${snap} built`);
	assert.equal(scrubSecrets(`agent ${agent} ok`, cfg), `agent ${agent} ok`);
});

test("a vendor key on the same line hides the key, not the ids", () => {
	for (const id of [v7(), v4(), `snap_${alnum(21)}`]) {
		const key = `gh${"p_"}${alnum(33)}`;
		const out = scrubSecrets(`run ${id} used ${key}`, cfg);
		assert.ok(out.includes(id), "the id was hidden");
		assert.ok(!out.includes(key), "the key leaked");
	}
});
