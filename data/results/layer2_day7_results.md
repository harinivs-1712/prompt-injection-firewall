# Layer 2 Day 7: tool-output inspection results

These traces use a deterministic scripted scanner with placeholder markers. They are functional checks, not measured detection accuracy. A masked or held output does not prove that an agent behaves safely; inspection happens after the tool already ran.

| Trace | Levels | Output action | Agent view | Reasons / notes |
|---|---|---|---|---|
| clean output | none:1 | PASS | original | OUTPUT_PASSED |
| medium output | medium:1 | PASS | original | OUTPUT_PASSED |
| high output held | none:1, high:1 | HOLD | withheld | OUTPUT_HELD |
| high output masked | none:2, high:1 | MASK | masked | OUTPUT_MASKED |
| unreviewed output | needs_review:1 | PASS | marked | OUTPUT_UNREVIEWED |
| oversize output truncated | none:4 | PASS | truncated/marked | OUTPUT_OVERSIZE, OUTPUT_PASSED |
| structured output masked at path | none:2, high:1 | MASK | masked | OUTPUT_MASKED |
| non-text output marked | needs_review | PASS | marked | OUTPUT_NOT_TEXT, OUTPUT_UNREVIEWED |
| scan failure held | needs_review | HOLD | withheld | OUTPUT_SCAN_FAILED |
| output scan disabled | none | PASS | original | OUTPUT_SCAN_DISABLED |
| poisoned output then dependent action | medium:1 | PASS | original | OUTPUT_PASSED; follow-up allow (needs Day 8 linking; not counted as blocked) |

The poisoned-output follow-up call passes the Day 6 rules because the firewall does not yet link inspected segments to later arguments. It is labeled as a Day 8 provenance task and is not counted as blocked. Tool outputs may already have caused side effects before inspection.

Limits: the scripted scanner is not Layer 1; masking removes only flagged spans and remaining text can still influence the agent; holding may block useful work; judge calls consume the session budget; unreviewed content is passed with a mark by default; JSON keys and non-string values are not scanned; oversize and depth-limited content may remain unscanned; span matching is best-effort.
