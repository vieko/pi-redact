// pi-redact#6: a signed upload URL (Linear `?signature=<JWT>`) is hidden as
// one placeholder. Week 48 counted each URL as four or five values: the
// standard HS256 header, once known, was hidden first and cut every later
// JWT apart, and short pieces of the payload were left in the clear.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { test } from "node:test";
import { buildConfig } from "../extensions/pi-redact.ts";
import { collect, scrubSecrets } from "../src/detect.ts";

const cfg = buildConfig({});
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const HEADER = b64({ alg: "HS256", typ: "JWT" });
const TAG = /^\[REDACTED-SECRET-[0-9a-f]{8}\]$/;

function signedUrl(): { url: string; jwt: string } {
	const path = `/${randomUUID()}/${randomUUID()}/${randomUUID()}`;
	const iat = 1795000000 + Math.floor(Math.random() * 1e6);
	const jwt = `${HEADER}.${b64({ path, iat, exp: iat + 300 })}.${randomBytes(32).toString("base64url")}`;
	return { url: `https://uploads.linear.app${path}?signature=${jwt}`, jwt };
}

const signature = (out: string) => out.match(/signature=([^)\s]*)/)?.[1] ?? "";

test("a JWT whose header is already known is hidden whole", () => {
	// The bare header, hidden once, becomes a known value.
	scrubSecrets(`token=${HEADER}`, cfg);
	for (let i = 0; i < 3; i++) {
		const { url, jwt } = signedUrl();
		const { value, tags } = collect(() => scrubSecrets(`![image.png](${url})`, cfg));
		assert.equal(tags.size, 1);
		assert.match(signature(value), TAG);
		for (const part of jwt.split(".")) assert.ok(!value.includes(part), "a JWT part leaked");
	}
});

test("a JWT cut after its payload is one value and does not split later ones", () => {
	const { url, jwt } = signedUrl();
	const cut = url.slice(0, url.length - 60);
	const { value, tags } = collect(() => scrubSecrets(`![image.png](${cut}… (truncated`, cfg));
	assert.equal(tags.size, 1);
	assert.ok(!value.includes(jwt.split(".")[1]!.slice(0, 20)), "the payload leaked");
	const next = signedUrl();
	const later = collect(() => scrubSecrets(`![image.png](${next.url})`, cfg));
	assert.equal(later.tags.size, 1);
	assert.match(signature(later.value), TAG);
});

test("a random key and a bearer JWT beside the URL stay hidden", () => {
	const key = `gh${"p_"}${randomBytes(27).toString("base64url").replace(/[-_]/g, "x")}`;
	const { url, jwt } = signedUrl();
	const bearer = signedUrl().jwt;
	const out = scrubSecrets(`${url} ${key} Authorization: Bearer ${bearer}`, cfg);
	for (const v of [key, jwt, bearer]) assert.ok(!out.includes(v), "a secret leaked");
});
