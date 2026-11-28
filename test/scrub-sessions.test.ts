// Contract for scripts/scrub-sessions.ts: it rewrites saved sessions in place
// and old history cannot be restored, so what it touches and what it leaves
// is pinned here. The script runs as a child process against a temporary
// --dir. The one key-shaped value is generated at run time, new on each run,
// so no key-shaped string sits in the repo.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("../scripts/scrub-sessions.ts", import.meta.url));
const REPO = dirname(dirname(SCRIPT));

/** The prefix of the vendor shape the script looks for; a prefix alone is not a key. */
const PREFIX = "vck_";
// Random on every run and never a real credential: the script only acts on a
// vendor-shaped value, so the test has to make one. It opens nothing.
const generatedTestKey = `${PREFIX}${randomBytes(24).toString("hex")}`;

const TAG = /\[REDACTED-SECRET-[0-9a-f]{8}\]/g;
/** The placeholder the script writes for `value`: the first 8 hex of its sha256. */
const tagOf = (value: string): string => `[REDACTED-SECRET-${createHash("sha256").update(value).digest("hex").slice(0, 8)}]`;

const STAMP = "2025-03-04T05:06:07.000Z";
const CHANNEL = "message/toolResult/bash :: content.text";

type Report = {
	mode: string;
	filesScanned: number;
	filesWithKeys: number;
	linesChanged: number;
	skippedLive: string[];
	errors: string[];
	keys: {
		tag: string;
		family: string;
		length: number;
		occurrences: number;
		sessions: number;
		firstSeen: string | null;
		lastSeen: string | null;
		origin: string | null;
		channels: Record<string, number>;
		sessionFiles: string[];
	}[];
};

/** A session header line: no key in it, so the script must leave it byte for byte. */
const header = (): string => JSON.stringify({ type: "session", version: 3, id: "s-1", timestamp: STAMP, cwd: "/tmp/project" });

/** A tool result whose output is `text`. */
const toolResult = (text: string): string =>
	JSON.stringify({
		type: "message",
		id: "m-1",
		parentId: "s-1",
		timestamp: STAMP,
		message: { role: "toolResult", toolName: "bash", content: [{ type: "text", text }] },
	});

/** An assistant turn that carries `signature` in the signed field `field`. */
const signedTurn = (field: string, signature: string): string =>
	JSON.stringify({
		type: "message",
		id: "m-2",
		parentId: "m-1",
		timestamp: STAMP,
		message: { role: "assistant", content: [{ type: "thinking", thinking: "plan", [field]: signature }, { type: "text", text: "done" }] },
	});

/** A fresh root with a `sessions/project` folder inside, removed when the test ends. */
function sandbox(t: TestContext): { root: string; dir: string; project: string } {
	const root = mkdtempSync(join(tmpdir(), "pi-redact-scrub-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const dir = join(root, "sessions");
	const project = join(dir, "project");
	mkdirSync(project, { recursive: true });
	return { root, dir, project };
}

/** Writes a session file from `lines`, last modified `ageMin` minutes ago, on a whole second. */
function session(file: string, lines: string[], ageMin: number): string {
	writeFileSync(file, `${lines.join("\n")}\n`);
	const when = new Date(Math.floor((Date.now() - ageMin * 60_000) / 1000) * 1000);
	utimesSync(file, when, when);
	return file;
}

/**
 * Runs the script on `dir` with `--report`, and returns the parsed report.
 * HOME points into the sandbox, so a run can never reach real sessions.
 */
function scrub(root: string, dir: string, ...args: string[]): { report: Report; text: string; stderr: string } {
	const out = join(root, "report.json");
	const r = spawnSync(process.execPath, [SCRIPT, "--dir", dir, "--report", out, ...args], {
		cwd: REPO,
		encoding: "utf8",
		env: { ...process.env, HOME: root, USERPROFILE: root },
	});
	assert.equal(r.status, 0, r.stderr);
	const text = readFileSync(out, "utf8");
	return { report: JSON.parse(text) as Report, text, stderr: r.stderr };
}

test("a dry run changes no file, and its report counts the leak", (t) => {
	const { root, dir, project } = sandbox(t);
	const leaky = session(join(project, "leaky.jsonl"), [header(), toolResult(`API_KEY=${generatedTestKey}\nok`), toolResult(`again ${generatedTestKey}`)], 120);
	const clean = session(join(project, "clean.jsonl"), [header(), toolResult("nothing to see")], 120);
	const before = { leaky: readFileSync(leaky, "utf8"), clean: readFileSync(clean, "utf8"), mtime: statSync(leaky).mtimeMs };

	const { report, text, stderr } = scrub(root, dir, "--skip-recent-min", "0");

	assert.equal(readFileSync(leaky, "utf8"), before.leaky, "the leaky file is byte for byte the same");
	assert.equal(readFileSync(clean, "utf8"), before.clean);
	assert.equal(statSync(leaky).mtimeMs, before.mtime);
	assert.deepEqual(readdirSync(project).sort(), ["clean.jsonl", "leaky.jsonl"], "no temp file is left behind");

	assert.equal(report.mode, "dry-run");
	assert.equal(report.filesScanned, 2);
	assert.equal(report.filesWithKeys, 1);
	assert.equal(report.linesChanged, 2);
	assert.deepEqual(report.skippedLive, []);
	assert.deepEqual(report.errors, []);
	assert.equal(report.keys.length, 1, "one distinct key, seen twice");
	const key = report.keys[0]!;
	assert.equal(key.tag, tagOf(generatedTestKey));
	assert.equal(key.family, PREFIX);
	assert.equal(key.length, generatedTestKey.length);
	assert.equal(key.occurrences, 2);
	assert.equal(key.sessions, 1);
	assert.equal(key.firstSeen, STAMP);
	assert.equal(key.lastSeen, STAMP);
	assert.equal(key.origin, CHANNEL);
	assert.deepEqual(key.channels, { [CHANNEL]: 2 });
	assert.deepEqual(key.sessionFiles, [join("/project", "leaky.jsonl")]);

	assert.ok(!text.includes(generatedTestKey), "the report never holds the key");
	assert.match(stderr, /^dry-run: 2 files, 1 with keys, 2 lines, 1 distinct keys, 0 live skipped, 0 errors$/m);
});

test("--write replaces a vendor-shaped key with [REDACTED-SECRET-<8 hex>] and keeps the mtime", (t) => {
	const { root, dir, project } = sandbox(t);
	// A line pi would not write itself: odd spacing, to show an untouched line is not re-serialized.
	const spaced = `{"type": "model_change",  "id": "c-1", "timestamp": "${STAMP}"}`;
	const lines = [header(), spaced, toolResult(`API_KEY=${generatedTestKey}\nand ${generatedTestKey} again`), toolResult("plain output")];
	const file = session(join(project, "leaky.jsonl"), lines, 1);
	const before = statSync(file);

	const { report, text } = scrub(root, dir, "--write", "--skip-recent-min", "0");

	const after = readFileSync(file, "utf8");
	assert.ok(!after.includes(generatedTestKey), "no key is left in the file");
	assert.deepEqual(after.match(TAG), [tagOf(generatedTestKey), tagOf(generatedTestKey)]);
	const out = after.split("\n");
	assert.equal(out.length, lines.length + 1, "same number of lines, trailing newline kept");
	for (const i of [0, 1, 3]) assert.equal(out[i], lines[i], `line ${i + 1} is byte for byte the same`);
	const expected = JSON.parse(lines[2]!);
	expected.message.content[0].text = `API_KEY=${tagOf(generatedTestKey)}\nand ${tagOf(generatedTestKey)} again`;
	assert.deepEqual(JSON.parse(out[2]!), expected, "only the key changed in the rewritten line");

	assert.equal(statSync(file).mtimeMs, before.mtimeMs, "mtime is kept");
	assert.deepEqual(readdirSync(project), ["leaky.jsonl"], "no temp file is left behind");

	assert.equal(report.mode, "write");
	assert.equal(report.filesWithKeys, 1);
	assert.equal(report.linesChanged, 1);
	assert.deepEqual(report.skippedLive, []);
	assert.deepEqual(report.errors, []);
	assert.deepEqual(report.keys.map((k) => [k.tag, k.occurrences]), [[tagOf(generatedTestKey), 1]]);
	assert.ok(!text.includes(generatedTestKey), "the report never holds the key");
});

for (const field of ["thinkingSignature", "signature"]) {
	test(`a key inside ${field} is left as it is`, (t) => {
		const { root, dir, project } = sandbox(t);
		const file = session(join(project, "signed.jsonl"), [header(), signedTurn(field, `sig:${generatedTestKey}:end`)], 120);
		const before = readFileSync(file, "utf8");
		const mtime = statSync(file).mtimeMs;

		const { report } = scrub(root, dir, "--write", "--skip-recent-min", "0");

		assert.equal(readFileSync(file, "utf8"), before, "the file is byte for byte the same");
		assert.equal(statSync(file).mtimeMs, mtime);
		assert.equal(report.filesScanned, 1);
		assert.equal(report.filesWithKeys, 0);
		assert.equal(report.linesChanged, 0);
		assert.deepEqual(report.keys, []);
		assert.deepEqual(report.errors, []);
	});
}

test("a file modified within --skip-recent-min is skipped", (t) => {
	const { root, dir, project } = sandbox(t);
	const recent = session(join(project, "recent.jsonl"), [header(), toolResult(`live ${generatedTestKey}`)], 30);
	const old = session(join(project, "old.jsonl"), [header(), toolResult(`old ${generatedTestKey}`)], 120);
	const before = readFileSync(recent, "utf8");
	const mtime = statSync(recent).mtimeMs;

	// 30 minutes old, inside a 60 minute window: skipped, but still counted.
	const { report, stderr } = scrub(root, dir, "--write", "--skip-recent-min", "60");

	assert.equal(readFileSync(recent, "utf8"), before, "the recent file is byte for byte the same");
	assert.equal(statSync(recent).mtimeMs, mtime);
	assert.deepEqual(readFileSync(old, "utf8").match(TAG), [tagOf(generatedTestKey)], "the old file beside it is rewritten");
	assert.deepEqual(report.skippedLive, [recent]);
	assert.equal(report.filesWithKeys, 2);
	assert.equal(report.keys.length, 1);
	assert.equal(report.keys[0]!.occurrences, 2);
	assert.deepEqual(report.errors, []);
	assert.match(stderr, /1 live skipped/);
});
