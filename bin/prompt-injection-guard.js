#!/usr/bin/env node
/**
 * prompt-injection-guard — scan the files an agent reads automatically.
 *
 *   prompt-injection-guard AGENTS.md
 *   prompt-injection-guard --rules rules.json AGENTS.md
 *   prompt-injection-guard --dir ~/.config/opencode
 *   prompt-injection-guard --sanitise AGENTS.md
 */
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs"
import { join } from "node:path"
import { scanFiles, sanitise, loadRules } from "../src/index.js"

// --- CLI shell: --help / --version -------------------------------------------
const HELP = "prompt-injection-guard — Find the instructions hidden in the files your agent reads by itself.\n\nUSAGE\n  prompt-injection-guard AGENTS.md\n  prompt-injection-guard --rules rules.json AGENTS.md\n  prompt-injection-guard --dir ~/.config/opencode\n  prompt-injection-guard --sanitise AGENTS.md\n\nCOMMANDS / OPTIONS\n  --dir <path>    scan a directory tree (max depth 3)\n  --rules <file>  load custom rules from a JSON file (built-in set stays default)\n  --sanitise      print the file with comments and invisible characters removed\n\nExit code 1 when a critical finding is present.\n\nMIT · https://github.com/rustemmustafingovua-byte"
const VERSION = "0.1.0"
if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(HELP)
  process.exit(0)
}
if (process.argv.includes("--version") || process.argv.includes("-V")) {
  console.log(VERSION)
  process.exit(0)
}


const argv = process.argv.slice(2)
const arg = (n) => {
  const i = argv.indexOf(n)
  return i >= 0 ? argv[i + 1] : undefined
}
const dir = arg("--dir")
const rulesPath = arg("--rules")
const consumedValues = new Set([dir, rulesPath].filter(Boolean))
const files = []
if (dir && existsSync(dir)) {
  const walk = (d, depth = 0) => {
    if (depth > 3) return
    for (const e of readdirSync(d)) {
      if (e.startsWith(".") || e === "node_modules") continue
      const p = join(d, e)
      const st = statSync(p)
      if (st.isDirectory()) walk(p, depth + 1)
      else if (/\.(md|txt|json|jsonc|ya?ml)$/i.test(e) && st.size < 400_000)
        files.push({ name: p, content: readFileSync(p, "utf8") })
    }
  }
  walk(dir)
} else {
  for (const f of argv.filter((a) => !a.startsWith("--") && !consumedValues.has(a))) {
    if (existsSync(f)) files.push({ name: f, content: readFileSync(f, "utf8") })
  }
}
if (!files.length) {
  console.error("usage: prompt-injection-guard [--rules <rules.json>] <file...> | --dir <path>")
  process.exit(2)
}

if (argv.includes("--sanitise")) {
  for (const f of files) {
    const clean = sanitise(f.content)
    if (clean !== f.content) {
      console.error(`sanitising ${f.name}`)
      process.stdout.write(clean)
    }
  }
  process.exit(0)
}

const rules = rulesPath ? loadRules(rulesPath) : undefined
const report = scanFiles(files, { rules })
console.log(`\nscanned ${files.length} file(s)  ·  score ${report.score}/100  ·  ${report.verdict}\n`)
for (const f of report.findings) {
  const mark = f.severity === "critical" ? "✗" : f.severity === "high" ? "!" : "·"
  console.log(`  ${mark} [${f.severity}] ${f.id}  in ${f.where}  (${f.count}x)`)
  console.log(`      ${f.excerpt}`)
  console.log(`      ${f.why}\n`)
}
if (!report.findings.length) console.log("  nothing suspicious found\n")
process.exit(report.bySeverity.critical ? 1 : 0)
