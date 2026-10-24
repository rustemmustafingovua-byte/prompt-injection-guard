/**
 * prompt-injection-guard — find instructions hidden in the places an agent
 * reads automatically.
 *
 * Agents read rules files, tool descriptions and READMEs without a human in
 * the loop. Anything that looks like an instruction ("ignore previous",
 * "send the key to…") or that hides text (zero-width characters, HTML
 * comments, base64 blobs) is a risk. This scans and reports.
 */
import { readFileSync } from "node:fs"

export const PATTERNS = [
  { id: "ignore-previous", severity: "critical", re: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i, why: "classic instruction override" },
  { id: "disregard-rules", severity: "critical", re: /disregard\s+(the\s+)?(system|previous)\s+(prompt|rules?|instructions?)/i, why: "instruction override" },
  { id: "exfiltrate-secret", severity: "critical", re: /(send|post|upload|exfiltrate|leak)\s+(the\s+)?(api[_ -]?key|secret|token|private key|env)/i, why: "asks for credentials" },
  { id: "hide-in-markdown", severity: "high", re: /<!--[^>]{0,400}?(ignore|system|you\s+must|always|secret|token)/is, why: "instructions hidden in an HTML comment" },
  { id: "invisible-unicode", severity: "high", re: /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/, why: "zero-width or bidi control characters" },
  { id: "fake-system", severity: "high", re: /^\s*(system|assistant)\s*:/im, why: "looks like a role marker" },
  { id: "always-do", severity: "medium", re: /\balways\s+(call|use|send|run|execute)\b/i, why: "imperative injected into prose" },
  { id: "urgent-override", severity: "medium", re: /\b(urgent|important)\s*[:!].{0,80}\b(ignore|must|do not stop)\b/i, why: "pressure framing" },
  { id: "base64-blob", severity: "info", re: /[A-Za-z0-9+/]{120,}={0,2}/, why: "long base64 blob — decode before trusting" },
  { id: "external-post", severity: "medium", re: /curl\s+[^\n]*https?:\/\/[^\s|]+/i, why: "embedded shell command" },
  { id: "policy-refresh", severity: "critical", re: /(policy|rule|constraint|directive|configuration)s?\s+(refresh|rotation|update|swap|change)s?\b|\b(earlier|previous|prior|former)\s+(policy|policies|rule|rules|constraint|constraints|directive|directives)\b[^.]{0,40}\b(no longer|not in force|void|voided|superseded|nullified|disapplied|replaced|revoked|lifted|dropped)\b/i, why: "claims the rules were replaced — policy-swap injection" },
  { id: "authority-transfer", severity: "critical", re: /\b(authority|control|command)\b[^.]{0,60}\b(transferred|delegated|handed over|moved|escalated)\b|\b(operator|owner|admin|developer)s?\s+(channel|notice|message|update)\b[^.]{0,60}\b(only|sole|real|authoritative)\b/i, why: "claims authority was transferred — delegation injection" },
  { id: "continuation-trick", severity: "high", re: /(previous|prior|above|earlier|last)\s+(turn|message|reply|response|context|configuration|config|prompt)\b[^.]{0,40}\b(truncated|cut off|overflow|garbled|dropped|partial)\b|\b(remaining|rest of the) lines? (of )?(your|the) (configuration|config|instructions|system)\b|\bcontext window (truncated|overflowed|exceeded)\b/i, why: "fake truncated context — continuation injection" },
  { id: "code-completion-trick", severity: "high", re: /\b(complete|finish|fill in|continue)\s+(the\s+following|this)\s+(python|javascript|typescript|code|function|method|snippet|script)\b|\breturn\s*["']\s*$/im, why: "asks the model to complete code — string-completion injection" },
  { id: "conformance-test", severity: "medium", re: /\b(automated|automatic|policy)\s+(conformance|compliance|verification|eval(uation)?)\s+(test|check|run|harness)\b|\bthe harness (requires|expects|needs)\b/i, why: "pretends to be a test harness — legitimises the request" },
  { id: "role-continuation", severity: "high", re: /^\s*assistant\s*$/im, why: "bare role header — continuation injection" },
  { id: "authority-header", severity: "high", re: /^\s*(system[-_ ]level\s+update|operator\s+notice|admin\s+notice|priority\s+update|configuration\s+refresh|policy\s+refresh|delegation\s+notice|security\s+directive)\b/im, why: "impersonates an authoritative notice" },
  { id: "only-rule-matters", severity: "medium", re: /\bthe only (rule|directive|instruction|constraint)s? that (matters|applies|counts|is in force)\b|\bthe (directive|rule)s? that matters\b/i, why: "declares a single overriding rule" },
  { id: "no-refusal", severity: "high", re: /\bwithout\s+(commentary|refusals?|caveats?|disclaimers?|warnings?)\b|\bdo not (refuse|decline|question|verify|check)\b|\bno longer (in force|apply|valid)\b/i, why: "tells the model to stop refusing" },
]

/** Normalise a custom rule entry or load a user-editable JSON rules file. */
export function normalizeRule(rule) {
  if (!rule || typeof rule !== "object") throw new Error("invalid rule entry")
  const id = String(rule.id || "").trim()
  if (!id) throw new Error("rule is missing id")
  const severity = rule.severity || "high"
  const why = rule.why || rule.description || "custom rule"
  if (rule.re instanceof RegExp) return { id, severity, re: rule.re, why }
  const source = rule.re ?? rule.pattern ?? rule.regex
  if (typeof source !== "string" || !source) throw new Error(`rule "${id}" is missing pattern/re`)
  const flags = typeof rule.flags === "string" ? rule.flags : "i"
  return { id, severity, re: new RegExp(source, flags), why }
}

/** Load user-editable rules from a JSON file path or parsed JSON object/array, merged onto built-in PATTERNS by default. */
export function loadRules(input, { includeDefaults = true } = {}) {
  const raw = typeof input === "string" ? JSON.parse(readFileSync(input, "utf8")) : input
  const list = Array.isArray(raw) ? raw : Array.isArray(raw?.rules) ? raw.rules : []
  const useDefaults = typeof raw?.extends === "boolean" ? raw.extends : includeDefaults
  const custom = list.map(normalizeRule)
  if (!useDefaults) return custom
  const customIds = new Set(custom.map((r) => r.id))
  return [...PATTERNS.filter((p) => !customIds.has(p.id)), ...custom]
}

function resolveRules(rules) {
  if (!rules) return PATTERNS
  if (typeof rules === "string") return loadRules(rules)
  if (Array.isArray(rules)) {
    const normalized = rules.map((r) => (r?.re instanceof RegExp ? r : normalizeRule(r)))
    const customIds = new Set(normalized.map((r) => r.id))
    return [...PATTERNS.filter((p) => !customIds.has(p.id)), ...normalized]
  }
  return loadRules(rules)
}

/** Scan a string. */
export function scan(text, { where = "text", rules } = {}) {
  const s = String(text || "")
  const activeRules = resolveRules(rules)
  const findings = []
  for (const p of activeRules) {
    const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g")
    let m
    let count = 0
    let firstIndex = -1
    while ((m = re.exec(s)) !== null) {
      count++
      if (firstIndex < 0) firstIndex = m.index
      if (m.index === re.lastIndex) re.lastIndex++
    }
    if (count) {
      findings.push({
        id: p.id,
        severity: p.severity,
        where,
        count,
        firstIndex,
        excerpt: s.slice(Math.max(0, firstIndex - 30), firstIndex + 70).replace(/\s+/g, " "),
        why: p.why,
      })
    }
  }
  return findings
}

/** Scan a whole file set (rules, tool descriptions, docs). */
export function scanFiles(files, { rules } = {}) {
  const activeRules = resolveRules(rules)
  const findings = []
  for (const f of files) {
    findings.push(...scan(f.content, { where: f.name, rules: activeRules }))
  }
  const bySeverity = { critical: 0, high: 0, medium: 0, info: 0 }
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1
  const score = Math.max(0, 100 - bySeverity.critical * 30 - bySeverity.high * 12 - bySeverity.medium * 5)
  return { findings, bySeverity, score, verdict: bySeverity.critical ? "unsafe" : bySeverity.high ? "suspicious" : "clean" }
}

/** Suggest a sanitised version: strip comments and invisible characters. */
export function sanitise(text) {
  let s = String(text || "")
  s = s.replace(/<!--[\s\S]*?-->/g, "")
  s = s.replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g, "")
  return s
}
