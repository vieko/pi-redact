/**
 * pi-redact
 *
 * Keeps secrets out of pi session transcripts. A key that reaches the
 * conversation is sent on every later turn, stored in the session .jsonl, and
 * replayed into forks and audits. This swaps each one for a stable
 * placeholder (`[REDACTED-SECRET-1a2b3c4d]`) and puts the real value back on
 * the way into a tool that runs on this machine, so commands keep working.
 *
 * Detection is vendored from ray-amjad/claude-code-mods (src/detect.ts). This
 * file maps its hooks onto pi events:
 *
 *   input               prompt text, before the agent sees it
 *   before_agent_start  AGENTS.md / CLAUDE.md context files (secrets only)
 *   tool_call           placeholder -> real value for local tools
 *   tool_result         real value -> placeholder in content/structured/details
 *   message_end         backstop for user, custom and toolResult messages
 *   context             request-local net over everything sent to the model
 *
 * Each value seen for the first time in a session is logged as a `pi-redact`
 * custom entry (counts and channel only, never the value), so audits can
 * tell how often and how secrets reach a session.
 *
 * The vault lives in memory. After /reload or a resume, old placeholders no
 * longer map to a value and reach tools as written.
 *
 * The footer shows `ø N`: distinct values kept out of this session's
 * transcript. It counts the `pi-redact` entries on the branch, so the
 * number survives /reload and resume even though the vault does not.
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	type Config,
	collect,
	escapeLiteralTags,
	findVendorKeys,
	makeConfig,
	mint,
	restore,
	scrubPii,
	scrubSecrets,
	type WalkState,
	walk,
} from "../src/detect.ts";

const NAME = "pi-redact";
const CONFIG_PATH = join(homedir(), ".pi", "agent", "pi-redact.json");

/** Tools that run on this machine and may receive real values. */
export const DEFAULT_RESTORE_TOOLS = "bash,powershell,write,edit,read,grep,find,ls";

/** Ids that look random but are public handles in our daily tooling. */
export const DEFAULT_ALLOW_PREFIXES = "dpl_,prj_,team_,wrun_,gen_01";

/**
 * Tools whose result holds live placeholders from nested calls. Their output
 * is not escaped, so the model can pass those placeholders on.
 */
export const LIVE_TAG_TOOLS = new Set(["codemode"]);

/**
 * A command that writes into git history or posts to GitHub. Placeholders
 * stay placeholders, so a commit message quoting one cannot carry the key.
 */
export const PUBLISHES =
	/\bgit\b(?:[ \t]+-[cC][ \t]+\S+|[ \t]+--?[\w-]+(?:=\S+)?)*[ \t]+(?:commit|tag|notes|send-email)\b|\bgh[ \t]+(?:issue|pr|release|gist|discussion|api|repo[ \t]+(?:create|edit))\b/;

const WITHHELD = `${NAME} could not scan this result, so it was withheld. Narrow the output (head, grep, offset) and retry.`;
const LIVE_TAG = /\[REDACTED-SECRET-[0-9a-f]{8}\]/g;

type Part = { type: string; text?: string };
type AnyMessage = { role: string; [key: string]: unknown };

function loadOptions(path: string): Record<string, unknown> {
	if (!existsSync(path)) return {};
	try {
		const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
		return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

export function buildConfig(options: Record<string, unknown>): Config {
	return makeConfig({
		restoreTools: DEFAULT_RESTORE_TOOLS,
		...options,
		allowPrefixes: [DEFAULT_ALLOW_PREFIXES, options.allowPrefixes].filter(Boolean).join(","),
	});
}

const countHidden = (tags: Set<string>): number => [...tags].filter((t) => !t.startsWith("[REDACTED-LITERAL-")).length;

/** Text parts of a content field (string or parts array), rewritten by `fn`. */
function mapContent<T>(content: T, fn: (s: string) => string): T {
	if (typeof content === "string") return fn(content) as T;
	if (!Array.isArray(content)) return content;
	let changed = false;
	const out = content.map((p: Part) => {
		if (p?.type !== "text" || typeof p.text !== "string") return p;
		const text = fn(p.text);
		if (text === p.text) return p;
		changed = true;
		return { ...p, text };
	});
	return (changed ? out : content) as T;
}

export interface RedactOptions {
	/** Overrides ~/.pi/agent/pi-redact.json, for tests. */
	options?: Record<string, unknown>;
}

export function createRedactor(pi: ExtensionAPI, init: RedactOptions = {}): void {
	const cfg = buildConfig(init.options ?? loadOptions(CONFIG_PATH));
	let enabled = true;
	let hiddenTotal = 0;
	let kept = 0;
	let ui: ExtensionContext | undefined;
	const showStatus = (): void => {
		if (!ui?.hasUI || kept <= 0) return;
		try {
			ui.ui.setStatus(NAME, ui.ui.theme.fg("dim", `ø ${kept}`));
		} catch {
			// The context went stale (session replaced); the next session_start resets it.
		}
	};
	const handedById = new Map<string, Set<string>>();
	const contextMemo = new WeakMap<object, AnyMessage>();
	const tracked = new Set<string>();

	// One entry per channel event that brought in values not seen before.
	// `vendor` counts the ones with a known vendor shape (high confidence);
	// the rest came from entropy rules and may be false positives.
	const track = (tags: Set<string>, source: string): void => {
		const fresh = [...tags].filter((t) => !t.startsWith("[REDACTED-LITERAL-") && !tracked.has(t));
		if (fresh.length === 0) return;
		for (const t of fresh) tracked.add(t);
		kept += fresh.length;
		showStatus();
		const vendor = fresh.filter((t) => findVendorKeys(restore(t)).length > 0).length;
		try {
			pi.appendEntry(NAME, { source, values: fresh.length, vendor });
		} catch {
			// Tracking is best-effort; redaction already happened.
		}
	};

	const scrub = (text: string): string => {
		let out = text;
		if (cfg.secrets) out = scrubSecrets(out, cfg);
		if (cfg.pii) out = scrubPii(out, cfg);
		return out;
	};
	const secretsOnly = (text: string): string => (cfg.secrets ? scrubSecrets(text, cfg) : text);

	const report = (ctx: ExtensionContext | undefined, n: number, where: string): void => {
		if (n <= 0) return;
		hiddenTotal += n;
		if (!ctx?.hasUI) return;
		if (cfg.notify && where) ctx.ui.notify(`${NAME}: hid ${n} value(s) from ${where}`, "info");
	};

	// Every real value one call was handed, so its output hides them again
	// even when no detector would fire on the bare value.
	const rehide = (text: string, handed: Set<string> | undefined): string => {
		if (!handed || handed.size === 0) return text;
		let out = text;
		for (const v of [...handed].sort((a, b) => b.length - a.length)) {
			if (v.length >= 4 && out.includes(v)) out = out.split(v).join(mint("SECRET", v));
		}
		return out;
	};

	pi.on("session_start", (_event, ctx) => {
		ui = ctx;
		kept = 0;
		for (const e of ctx.sessionManager.getBranch() as { type: string; customType?: string; data?: { values?: number } }[]) {
			if (e.type === "custom" && e.customType === NAME) kept += e.data?.values ?? 0;
		}
		if (ctx.hasUI) ctx.ui.setStatus(NAME, undefined);
		showStatus();
	});

	// 1. What the user types. `!cmd` is the user's own shell and runs as typed.
	pi.on("input", (event, ctx) => {
		if (!enabled || event.text.startsWith("!")) return { action: "continue" as const };
		try {
			const { value, tags } = collect(() => scrub(event.text));
			if (tags.size === 0) return { action: "continue" as const };
			report(ctx, countHidden(tags), "the prompt");
			track(tags, `prompt:${event.source}`);
			return { action: "transform" as const, text: value, images: event.images };
		} catch {
			if (ctx.hasUI) ctx.ui.notify(`${NAME} failed to scan the prompt, so it was not sent.`, "error");
			return { action: "handled" as const };
		}
	});

	// 2. Context files (AGENTS.md and friends). Secrets only: the email in
	//    them is the user's own.
	pi.on("before_agent_start", (event) => {
		if (!enabled || !cfg.secrets) return;
		const { tags } = collect(() => {
			for (const file of event.systemPromptOptions.contextFiles) file.content = secretsOnly(file.content);
		});
		track(tags, "context-file");
	});

	// 3. Placeholders become real values for tools that run here. Fails
	//    closed: pi blocks the tool when a tool_call handler throws.
	pi.on("tool_call", (event) => {
		if (!enabled || !cfg.restore || !cfg.restoreTools.has(event.toolName)) return;
		const input = event.input as Record<string, unknown>;
		if (event.toolName === "bash" && typeof input.command === "string" && PUBLISHES.test(input.command)) return;
		const handed = new Set<string>();
		const restoreTracked = (s: string): string =>
			restore(s) === s
				? s
				: s.replace(LIVE_TAG, (tag) => {
						const v = restore(tag);
						if (v !== tag) handed.add(v);
						return v;
					});
		const restored = walk(input, restoreTracked) as Record<string, unknown>;
		if (handed.size === 0) return;
		for (const key of Object.keys(restored)) input[key] = restored[key];
		handedById.set(event.toolCallId, handed);
	});

	// 4. Every tool result, nested codemode calls included. pi passes the raw
	//    result on when a handler throws, so failures withhold explicitly.
	pi.on("tool_result", (event, ctx) => {
		const handed = handedById.get(event.toolCallId);
		handedById.delete(event.toolCallId);
		if (!enabled) return;
		try {
			const escape = !LIVE_TAG_TOOLS.has(event.toolName);
			const memo = new Map<string, string>();
			const clean = (s: string): string => {
				const done = memo.get(s);
				if (done !== undefined) return done;
				const out = rehide(scrub(escape ? escapeLiteralTags(s) : s), handed);
				memo.set(s, out);
				return out;
			};
			const detailsState: WalkState = { incomplete: false };
			const structuredState: WalkState = { incomplete: false };
			const { value, tags } = collect(() => ({
				content: mapContent(event.content, clean),
				structuredContent: event.structuredContent === undefined ? undefined : walk(event.structuredContent, clean, structuredState),
				details: event.details === undefined ? undefined : walk(event.details, clean, detailsState),
			}));
			if (tags.size === 0) return;
			report(ctx, countHidden(tags), "");
			track(tags, `tool:${event.toolName}${event.parentToolCallId ? ":nested" : ""}`);
			return {
				content: value.content,
				// Structured data the walker could not fully rewrite may still hold
				// the value; scripts then fall back to the text content.
				...(event.structuredContent === undefined || structuredState.incomplete
					? {}
					: { structuredContent: value.structuredContent as typeof event.structuredContent }),
				details: detailsState.incomplete ? undefined : value.details,
			};
		} catch {
			return { content: [{ type: "text" as const, text: WITHHELD }], details: undefined, isError: true };
		}
	});

	// 5. Backstop before persistence. No literal escaping here: tool_result
	//    already did it, and a second pass would turn live placeholders into
	//    quoted ones.
	pi.on("message_end", (event) => {
		if (!enabled) return;
		const message = event.message as unknown as AnyMessage;
		if (message.role !== "user" && message.role !== "custom" && message.role !== "toolResult") return;
		try {
			const { value: content, tags } = collect(() => mapContent(message.content, scrub));
			if (content === message.content) return;
			track(tags, `message:${message.role}`);
			return { message: { ...message, content } as unknown as typeof event.message };
		} catch {
			return { message: { ...message, content: [{ type: "text", text: WITHHELD }] } as unknown as typeof event.message };
		}
	});

	// 6. The last net, request-local: bashExecution output, custom messages
	//    appended while idle, and history from sessions recorded before this
	//    extension. Same value -> same placeholder, so the cached prefix holds.
	const cleanMessage = (message: AnyMessage): AnyMessage => {
		const cached = contextMemo.get(message);
		if (cached) return cached;
		let out = message;
		switch (message.role) {
			case "user":
			case "custom":
			case "toolResult": {
				const content = mapContent(message.content, scrub);
				if (content !== message.content) out = { ...message, content };
				break;
			}
			case "bashExecution": {
				const command = typeof message.command === "string" ? scrub(message.command) : message.command;
				const output = typeof message.output === "string" ? scrub(message.output) : message.output;
				if (command !== message.command || output !== message.output) out = { ...message, command, output };
				break;
			}
			case "compactionSummary":
			case "branchSummary": {
				const summary = typeof message.summary === "string" ? scrub(message.summary) : message.summary;
				if (summary !== message.summary) out = { ...message, summary };
				break;
			}
		}
		contextMemo.set(message, out);
		return out;
	};

	pi.on("context", (event) => {
		if (!enabled) return;
		let changed = false;
		const { value: messages, tags } = collect(() =>
			event.messages.map((m) => {
				const out = cleanMessage(m as unknown as AnyMessage);
				if (out !== (m as unknown)) changed = true;
				return out as unknown as typeof m;
			}),
		);
		track(tags, "context");
		return changed ? { messages } : undefined;
	});

	pi.registerCommand("redact", {
		description: "pi-redact status. `/redact off` or `/redact on` toggles it for this session.",
		handler: async (args, ctx) => {
			const arg = args.trim();
			if (arg === "off" || arg === "on") enabled = arg === "on";
			const restoreList = cfg.restore ? [...cfg.restoreTools].join(", ") : "off";
			ctx.ui.notify(
				`${NAME} ${enabled ? "on" : "OFF"}: ${hiddenTotal} value(s) hidden this session. Restore into: ${restoreList}. PII: ${cfg.pii ? "on" : "off"}.`,
				enabled ? "info" : "warning",
			);
		},
	});
}

export default function (pi: ExtensionAPI): void {
	createRedactor(pi);
}
