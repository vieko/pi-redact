/**
 * scrub-sessions: rewrite vendor-shaped keys out of saved pi sessions, and
 * report how many leaked, how often, and how they got in.
 *
 *   node scripts/scrub-sessions.ts [--write] [--dir ~/.pi/agent/sessions]
 *                                  [--report out.json] [--skip-recent-min 15]
 *
 * Dry run by default. Only high-confidence matches (vendor shapes and private
 * key blocks) are rewritten; entropy guesses are not, because old history
 * cannot be restored and a false positive would corrupt it for good. Each key
 * becomes `[REDACTED-SECRET-<sha256/8>]`, the same tag for the same key in
 * every file, so the report can track one key across sessions without
 * holding the value. Signature fields are never touched.
 *
 * Files that are open in a process or modified in the last N minutes are
 * skipped: pi appends to the live session file. Rewritten files keep their
 * mtime, so /resume ordering and session-audit windows do not move.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, renameSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { findVendorKeys } from "../src/detect.ts";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
	const i = args.indexOf(name);
	return i >= 0 ? args[i + 1] : undefined;
};
const WRITE = args.includes("--write");
const DIR = flag("--dir") ?? join(homedir(), ".pi", "agent", "sessions");
const REPORT = flag("--report");
const RECENT_MS = Number(flag("--skip-recent-min") ?? 15) * 60_000;

/** Fields whose value is signed or opaque; editing them breaks a resume. */
const SKIP_KEYS = new Set(["thinkingSignature", "signature", "textSignature", "encrypted_content", "id", "parentId"]);

/** A match that reads like a docs example or a test fixture, not a key. */
const FAKE = /(.)\1{5}|abcdef|123456|xxxx|example|sandbox|dummy|fake|test|0000/i;

type Occurrence = { file: string; ts: string; channel: string };
type KeyStats = { family: string; likelyFake: boolean; length: number; occurrences: Occurrence[] };

const keys = new Map<string, KeyStats>();
const errors: string[] = [];
let filesScanned = 0;
let filesChanged = 0;
let linesChanged = 0;
const skipped: string[] = [];

const tagFor = (value: string): string => `[REDACTED-SECRET-${createHash("sha256").update(value).digest("hex").slice(0, 8)}]`;

function openFiles(): Set<string> {
	try {
		const out = execFileSync("lsof", ["-Fn", "-c", "node", "-c", "pi", "-c", "bun"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
		return new Set(out.split("\n").filter((l) => l.startsWith("n") && l.endsWith(".jsonl")).map((l) => l.slice(1)));
	} catch {
		return new Set();
	}
}

function channelOf(entry: any, path: string[]): string {
	const m = entry.message;
	const parts = [entry.type];
	if (m?.role) parts.push(m.role);
	if (m?.role === "toolResult" && m.toolName) parts.push(m.toolName);
	if (m?.role === "custom" || entry.type === "custom_message") parts.push(m?.customType ?? entry.customType ?? "");
	const field = path.filter((p) => !/^\d+$/.test(p)).slice(-2).join(".");
	return `${parts.filter(Boolean).join("/")} :: ${field}`;
}

function scrubValue(value: unknown, path: string[], onHit: (v: string, family: string, path: string[]) => void): unknown {
	if (typeof value === "string") {
		const hits = findVendorKeys(value);
		if (hits.length === 0) return value;
		let out = value;
		for (const { value: v, family } of hits.sort((a, b) => b.value.length - a.value.length)) {
			if (!out.includes(v)) continue;
			onHit(v, family, path);
			out = out.split(v).join(tagFor(v));
		}
		return out;
	}
	if (Array.isArray(value)) {
		let changed = false;
		const out = value.map((v, i) => {
			const r = scrubValue(v, [...path, String(i)], onHit);
			if (r !== v) changed = true;
			return r;
		});
		return changed ? out : value;
	}
	if (value && typeof value === "object") {
		let changed = false;
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value)) {
			const r = SKIP_KEYS.has(k) ? v : scrubValue(v, [...path, k], onHit);
			if (r !== v) changed = true;
			out[k] = r;
		}
		return changed ? out : value;
	}
	return value;
}

function sessionFiles(dir: string): string[] {
	const out: string[] = [];
	for (const e of readdirSync(dir, { withFileTypes: true })) {
		const p = join(dir, e.name);
		if (e.isDirectory()) out.push(...sessionFiles(p));
		else if (e.name.endsWith(".jsonl")) out.push(p);
	}
	return out;
}

const open = openFiles();
const now = Date.now();
for (const file of sessionFiles(DIR)) {
	filesScanned++;
	const st = statSync(file);
	const raw = readFileSync(file, "utf8");
	// Cheap gate: most files hold no vendor key at all.
	if (findVendorKeys(raw).length === 0) continue;
	const lines = raw.split("\n");
	let fileChanged = false;
	const outLines = lines.map((line) => {
		if (!line.trim()) return line;
		let entry: any;
		try {
			entry = JSON.parse(line);
		} catch {
			return line;
		}
		const ts = entry.timestamp ?? entry.message?.timestamp ?? "";
		const scrubbed = scrubValue(entry, [], (v, family, path) => {
			const id = tagFor(v);
			const k = keys.get(id) ?? { family, likelyFake: FAKE.test(v), length: v.length, occurrences: [] };
			k.occurrences.push({ file, ts: typeof ts === "number" ? new Date(ts).toISOString() : String(ts), channel: channelOf(entry, path) });
			keys.set(id, k);
		});
		if (scrubbed === entry) return line;
		fileChanged = true;
		linesChanged++;
		return JSON.stringify(scrubbed);
	});
	if (!fileChanged) continue;
	filesChanged++;
	const live = open.has(file) || now - st.mtimeMs < RECENT_MS;
	if (live) {
		skipped.push(file);
		continue;
	}
	if (!WRITE) continue;
	const next = outLines.join("\n");
	// Verify before swapping: same line count, every line still parses, no key left.
	const check = next.split("\n");
	if (check.length !== lines.length || check.some((l) => l.trim() && (() => { try { JSON.parse(l); return false; } catch { return true; } })())) {
		errors.push(`verify failed, left as is: ${file}`);
		continue;
	}
	const tmp = `${file}.pi-redact-tmp`;
	writeFileSync(tmp, next, { mode: st.mode });
	const left = findVendorKeys(readFileSync(tmp, "utf8"));
	renameSync(tmp, file);
	utimesSync(file, st.atime, st.mtime);
	if (left.length > 0) errors.push(`${left.length} match(es) remain in signed fields or ids: ${file}`);
}

// ------------------------------------------------------------------ report

const report = {
	generatedAt: new Date().toISOString(),
	mode: WRITE ? "write" : "dry-run",
	dir: DIR,
	filesScanned,
	filesWithKeys: filesChanged,
	linesChanged,
	skippedLive: skipped,
	errors,
	keys: [...keys].map(([tag, k]) => {
		const files = new Set(k.occurrences.map((o) => o.file));
		const times = k.occurrences.map((o) => o.ts).filter(Boolean).sort();
		const channels: Record<string, number> = {};
		for (const o of k.occurrences) channels[o.channel] = (channels[o.channel] ?? 0) + 1;
		const first = [...k.occurrences].sort((a, b) => a.ts.localeCompare(b.ts))[0];
		return {
			tag,
			family: k.family,
			likelyFake: k.likelyFake,
			length: k.length,
			occurrences: k.occurrences.length,
			sessions: files.size,
			firstSeen: times[0] ?? null,
			lastSeen: times.at(-1) ?? null,
			origin: first?.channel ?? null,
			channels,
			sessionFiles: [...files].map((f) => f.replace(DIR, "")),
		};
	}),
};

const json = JSON.stringify(report, null, 2);
if (REPORT) writeFileSync(REPORT, json);
else console.log(json);
console.error(
	`${report.mode}: ${filesScanned} files, ${filesChanged} with keys, ${linesChanged} lines, ${keys.size} distinct keys, ${skipped.length} live skipped, ${errors.length} errors`,
);
