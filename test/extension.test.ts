// The extension end to end against a fake pi: what reaches the model, what a
// tool receives, and what lands in a persisted message. Fake keys are built
// at run time so no key-shaped string sits in the repo.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createRedactor } from "../extensions/pi-redact.ts";

const ABC = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789";
let seed = 0x5eed;
const body = (n: number): string => {
	let s = "";
	for (let i = 0; i < n; i++) {
		seed = (seed * 1103515245 + 12345) >>> 0;
		s += ABC[seed % ABC.length];
	}
	return `${s}Q7z`;
};

// Our own key shapes: AI Gateway, Linear, Slack bot, GitHub.
const GATEWAY = `v${"ck_"}${body(53)}`;
const LINEAR = `lin${"_api_"}${body(37)}`;
const SLACK = `xo${"xb-"}1034${body(6)}-${body(10)}-${body(21)}`;
const GITHUB = `gh${"p_"}${body(33)}`;
const TAG = /\[REDACTED-SECRET-[0-9a-f]{8}\]/;
const TAGS = /\[REDACTED-SECRET-[0-9a-f]{8}\]/g;

type Handler = (event: any, ctx: any) => any;

function harness(options: Record<string, unknown> = {}) {
	const handlers = new Map<string, Handler[]>();
	const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
	const notices: string[] = [];
	const entries: { type: string; data: any }[] = [];
	const statuses: (string | undefined)[] = [];
	const branch: any[] = [];
	const ctx = {
		hasUI: true,
		ui: { notify: (m: string) => notices.push(m), setStatus: (_k: string, t?: string) => statuses.push(t), theme: { fg: (_c: string, s: string) => s } },
		sessionManager: { getBranch: () => branch },
	};
	const pi = {
		on: (name: string, h: Handler) => {
			handlers.set(name, [...(handlers.get(name) ?? []), h]);
			return () => {};
		},
		registerCommand: (name: string, c: any) => commands.set(name, c),
		appendEntry: (type: string, data: any) => entries.push({ type, data }),
	};
	createRedactor(pi as any, { options });
	const fire = (name: string, event: any) => {
		let result: any;
		for (const h of handlers.get(name) ?? []) result = h(event, ctx);
		return result;
	};
	return { fire, notices, commands, ctx, entries, statuses, branch };
}

/** Runs one tool call: the model's input, the tool's output, the result. */
function toolRound(h: ReturnType<typeof harness>, toolName: string, input: Record<string, unknown>, run: (input: any) => string, id = "call-1"): { blocked: any; seen: any; result: any } {
	const call = { type: "tool_call", toolCallId: id, toolName, input };
	const blocked = h.fire("tool_call", call);
	if (blocked?.block) return { blocked, seen: undefined, result: undefined };
	const seen = structuredClone(call.input);
	const output = run(call.input);
	const event = { type: "tool_result", toolCallId: id, toolName, input: call.input, content: [{ type: "text", text: output }], isError: false, details: { full: output } };
	const result = h.fire("tool_result", event) ?? event;
	return { blocked, seen, result };
}

/** Pastes a key, returns its placeholder. */
function hide(h: ReturnType<typeof harness>, key: string): string {
	const r = h.fire("input", { type: "input", text: `use ${key} please`, source: "interactive" });
	assert.equal(r.action, "transform");
	assert.ok(!r.text.includes(key), "key reached the model");
	return r.text.match(TAG)![0];
}

test("the footer counts distinct values and survives a reload", () => {
	const h = harness();
	h.fire("session_start", { type: "session_start" });
	assert.equal(h.statuses.at(-1), undefined, "no status before anything is hidden");
	const key = GITHUB;
	hide(h, key);
	hide(h, key);
	assert.equal(h.statuses.at(-1), "redacted:1", "the same key twice is one value");
	// A reload is a fresh redactor over the same session entries.
	const again = harness();
	again.branch.push(...h.entries.map((e) => ({ type: "custom", customType: e.type, data: e.data })));
	again.fire("session_start", { type: "session_start" });
	assert.equal(again.statuses.at(-1), "redacted:1");
});

test("a pasted key becomes a placeholder, for each of our key shapes", () => {
	const h = harness();
	for (const key of [GATEWAY, LINEAR, SLACK, GITHUB]) hide(h, key);
	assert.ok(h.notices.some((n) => n.includes("hid 1 value(s) from the prompt")));
});

test("the same key keeps the same placeholder", () => {
	const h = harness();
	assert.equal(hide(h, GATEWAY), hide(h, GATEWAY));
});

test("a prompt without secrets passes untouched", () => {
	const h = harness();
	const r = h.fire("input", { type: "input", text: "fix the tests in src/app.ts at a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", source: "interactive" });
	assert.equal(r.action, "continue");
});

test("!cmd is the user's own shell and is not rewritten", () => {
	const h = harness();
	const r = h.fire("input", { type: "input", text: `!export KEY=${GATEWAY}`, source: "interactive" });
	assert.equal(r.action, "continue");
});

test("bash gets the real key, and its output comes back as the placeholder", () => {
	const h = harness();
	const tag = hide(h, LINEAR);
	const { seen, result } = toolRound(h, "bash", { command: `curl -H "Authorization: ${tag}" https://api.linear.app` }, (input) => `sent ${input.command}`);
	assert.ok(seen.command.includes(LINEAR), "bash did not get the real key");
	const text = result.content[0].text;
	assert.ok(!text.includes(LINEAR), "key came back to the model");
	assert.ok(text.includes(tag));
	assert.ok(!JSON.stringify(result.details).includes(LINEAR), "key left in details");
});

test("a short password handed to bash is hidden when printed bare", () => {
	const h = harness();
	const password = `Pw${body(9)}`;
	const r = h.fire("input", { type: "input", text: `DB_PASSWORD=${password}`, source: "interactive" });
	const tag = r.text.match(TAG)![0];
	const { seen, result } = toolRound(h, "bash", { command: `echo ${tag}` }, () => `${password}\n`);
	assert.ok(seen.command.includes(password));
	assert.ok(!result.content[0].text.includes(password), "bare password came back");
});

test("git commit and gh keep placeholders as written", () => {
	const h = harness();
	const tag = hide(h, GITHUB);
	for (const command of [`git commit -m "rotate ${tag}"`, `gh pr comment 1 --body "${tag}"`]) {
		const { seen } = toolRound(h, "bash", { command }, () => "ok");
		assert.ok(!seen.command.includes(GITHUB), `published the key: ${command}`);
	}
});

test("network and messaging tools never get the real value", () => {
	const h = harness();
	const tag = hide(h, SLACK);
	for (const toolName of ["send_message", "codemode", "mcp__linear__save_issue"]) {
		const { seen } = toolRound(h, toolName, { body: `token ${tag}` }, () => "ok");
		assert.ok(!seen.body.includes(SLACK), `${toolName} got the key`);
	}
});

test("write and edit get real values, so files keep working", () => {
	const h = harness();
	const tag = hide(h, GATEWAY);
	const w = toolRound(h, "write", { path: ".env", content: `AI_GATEWAY_API_KEY=${tag}\n` }, () => "wrote .env");
	assert.ok(w.seen.content.includes(GATEWAY));
	const e = toolRound(h, "edit", { path: ".env", edits: [{ oldText: tag, newText: "x" }] }, () => "edited");
	assert.ok(e.seen.edits[0].oldText === GATEWAY);
});

test("a key a tool prints is hidden, and a .env keeps its harmless lines", () => {
	const h = harness();
	const { result } = toolRound(h, "read", { path: ".env" }, () => `PORT=3000\nAI_GATEWAY_API_KEY=${GATEWAY}\n`);
	const text = result.content[0].text;
	assert.ok(text.includes("PORT=3000"));
	assert.ok(!text.includes(GATEWAY));
	assert.match(text, TAG);
});

test("a placeholder quoted in a file comes back quoted, not live", () => {
	const h = harness();
	const tag = hide(h, LINEAR);
	const { result } = toolRound(h, "read", { path: "notes.md" }, () => `the key was ${tag}`);
	const text = result.content[0].text;
	assert.ok(!text.includes(tag), "a quoted placeholder stayed live");
	assert.match(text, /\[REDACTED-LITERAL-[0-9a-f]{8}\]/);
});

test("codemode output keeps live placeholders from nested calls", () => {
	const h = harness();
	const tag = hide(h, LINEAR);
	const { result } = toolRound(h, "codemode", { code: "..." }, () => `nested bash said ${tag}`);
	assert.equal(result.content[0].text, `nested bash said ${tag}`);
});

test("structuredContent is rewritten with content, not dropped", () => {
	const h = harness();
	const event = {
		type: "tool_result",
		toolCallId: "s-1",
		toolName: "mcp__x__get",
		input: {},
		content: [{ type: "text", text: `token ${GITHUB}` }],
		structuredContent: { token: GITHUB, count: 2 },
		isError: false,
		details: undefined,
	};
	const r = h.fire("tool_result", event);
	assert.ok(r.structuredContent, "structuredContent dropped");
	assert.ok(!JSON.stringify(r.structuredContent).includes(GITHUB));
	assert.equal((r.structuredContent as any).count, 2);
});

test("a scan failure withholds the result instead of passing it raw", () => {
	const h = harness();
	const poisoned = { type: "text", get text(): string { throw new Error("boom"); } };
	const r = h.fire("tool_result", { type: "tool_result", toolCallId: "f-1", toolName: "bash", input: {}, content: [poisoned], isError: false, details: undefined });
	assert.equal(r.isError, true);
	assert.match(r.content[0].text, /withheld/);
});

test("context files are scrubbed before the system prompt is built", () => {
	const h = harness();
	const files = [{ path: "AGENTS.md", content: `deploy with VERCEL_TOKEN=${GATEWAY}` }];
	h.fire("before_agent_start", { type: "before_agent_start", prompt: "", systemPrompt: "", systemPromptOptions: { contextFiles: files } });
	assert.ok(!files[0]!.content.includes(GATEWAY));
});

test("message_end scrubs custom messages before they persist", () => {
	const h = harness();
	const message = { role: "custom", customType: "pi-post", content: `here is the key ${SLACK}`, display: true, timestamp: 1 };
	const r = h.fire("message_end", { type: "message_end", message });
	assert.ok(!r.message.content.includes(SLACK));
	assert.equal(r.message.customType, "pi-post");
});

test("message_end leaves assistant messages alone", () => {
	const h = harness();
	const message = { role: "assistant", content: [{ type: "text", text: `example ${GITHUB}` }] };
	assert.equal(h.fire("message_end", { type: "message_end", message }), undefined);
});

test("the context net hides old secrets and is stable across requests", () => {
	const h = harness();
	const messages = [
		{ role: "user", content: [{ type: "text", text: `old paste ${LINEAR}` }], timestamp: 1 },
		{ role: "bashExecution", command: "cat .env", output: `KEY=${GATEWAY}`, exitCode: 0, cancelled: false, truncated: false, timestamp: 2 },
		{ role: "assistant", content: [{ type: "thinking", thinking: "x", thinkingSignature: body(80) }] },
	];
	const first = h.fire("context", { type: "context", messages }).messages;
	const second = h.fire("context", { type: "context", messages: [...messages] }).messages;
	const dump = JSON.stringify(first);
	assert.ok(!dump.includes(LINEAR) && !dump.includes(GATEWAY));
	assert.equal(JSON.stringify(second), dump, "placeholders changed between requests: cache prefix breaks");
	assert.equal(first[2], messages[2], "assistant thinking signature was touched");
	assert.equal(dump.match(TAGS)!.length, 2);
});

test("our public ids and pi file names are kept", () => {
	const h = harness();
	const kept = [
		`dpl_${body(26)}`,
		"2026-10-09T23-42-26-443Z_01a12f3e-8c1d-4b2a-9e3f-0a1b2c3d4e5f.jsonl",
		`/var/folders/1s/${body(28).toLowerCase()}/T/pi-clipboard-1.png`,
	];
	for (const text of kept) {
		const { result } = toolRound(h, "bash", { command: "ls" }, () => text, `k-${text.length}`);
		assert.equal(result.content[0].text, text, `hid a public value: ${text.slice(0, 20)}`);
	}
});

test("/redact off stops rewriting for the session", async () => {
	const h = harness();
	await h.commands.get("redact")!.handler("off", h.ctx);
	const r = h.fire("input", { type: "input", text: `use ${GATEWAY}`, source: "interactive" });
	assert.equal(r.action, "continue");
	assert.ok(h.notices.at(-1)!.includes("OFF"));
});

test("each new value is logged once, with its channel and no value", () => {
	const h = harness();
	const key = `lin${"_api_"}${body(37)}`;
	hide(h, key);
	hide(h, key);
	toolRound(h, "bash", { command: "cat .env" }, () => `K=${key}\nG=${`v${"ck_"}${body(53)}`}`);
	const logged = h.entries.filter((e) => e.type === "pi-redact").map((e) => e.data);
	assert.deepEqual(logged, [
		{ source: "prompt:interactive", values: 1, vendor: 1 },
		{ source: "tool:bash", values: 1, vendor: 1 },
	]);
	assert.ok(!JSON.stringify(h.entries).includes(key));
});
