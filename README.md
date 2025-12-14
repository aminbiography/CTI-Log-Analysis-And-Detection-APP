Live URL: https://aminbiography.github.io/CTI-Log-Analysis-And-Detection-APP/

---

## Description for users (SOC analyst / IR operator)

### What this page is

This is a **browser-only log triage and detection helper**. You paste log lines into the relevant tab and the page performs **local parsing and detection** in your browser. It does not collect logs automatically and does not send your pasted data to external services.

### What problems it helps you solve

It supports four common workflows:

1. **Detect brute-force and password spray patterns** from authentication logs.
2. **Spot suspicious web requests** (probes, injection markers, traversal, scanning) and request bursts from access logs.
3. **Run lightweight custom detections** using a simple rule format (regex-based).
4. **Build an incident timeline** from mixed logs and export it as CSV.

### Tabs and how to use them

#### 1) Auth / Failed Login Detector

Use this when you want to identify likely brute force or password spray attempts.

Inputs:

* Log format: auto / Linux `auth.log` (sshd) / Windows Security text export / Generic key=value logs.
* Paste logs.
* Set thresholds:

  * **Aggregation window (minutes)** (default 10)
  * **Failures/IP/window** (default 8)
  * **Unique users/IP/window** (default 6) for spray detection
  * **Reset on success**: if enabled, a success can mark the end of an attack burst (useful for “success after failures” signals)

Outputs:

* Alerts grouped by IP and time window:

  * **BRUTE_FORCE** (many failures from one IP)
  * **PASSWORD_SPRAY** (many unique usernames targeted from one IP)
  * **SUCCESS_AFTER_FAILURES** (a success occurring after a non-trivial failure burst)
* KPIs: total alerts, suspicious IPs, targeted users
* “Samples” section per alert to review representative lines

What to do with results:

* Correlate suspicious IPs with endpoint telemetry, VPN logs, MFA failures, or WAF events.
* Validate whether the target accounts are real or decoys (honey users), and check for lockouts or compromised credentials.

#### 2) Web Access Log Scanner

Use this to triage access logs for signs of scanning, exploitation attempts, or anomalous bursts.

Inputs:

* Log format: combined/minimal/auto (the tool parses common structures).
* Burst settings:

  * **Burst window (seconds)** (default 30)
  * **Requests per IP per window** threshold (default 60)
* UA anomaly sensitivity: low/medium/high
* Include 200 responses: Yes/No (if “No”, it focuses on 4xx/5xx)

Detections/signals it looks for:

* Directory traversal (`../`, encoded traversal)
* SQL injection markers (`union select`, `or 1=1`, etc.)
* Command injection tokens (`;`, `&&`, plus common command words)
* SSRF-like calls to `localhost`, `127.0.0.1`, or cloud metadata IP `169.254.169.254`
* Sensitive file probes (`/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/admin`, `/etc/passwd`)
* Scanner UAs (`sqlmap`, `nikto`, `curl`, `python-requests`, etc.)
* Bursts (rate-based per IP)

Outputs:

* Alerts ranked by severity (HIGH/MEDIUM/LOW)
* Top burst summary (highest request burst)
* KPIs: alerts count, bursting IPs, top IP by request volume

What to do with results:

* Pivot the top IP(s) and paths into your SIEM, WAF, or reverse proxy logs.
* Check for corresponding auth anomalies and server errors.
* Verify whether suspicious 200s indicate successful discovery/exfiltration or false positives.

#### 3) Mini Rule Engine (YAML-lite)

Use this when you want quick, transparent, custom detections without a full SIEM query language.

Inputs:

* Rules in a minimal YAML-like list format:

  * `name`: rule name
  * `severity`: LOW/MEDIUM/HIGH/CRITICAL
  * `match`: regex string
  * `tags`: optional list
* Paste log lines to evaluate.
* Regex flag option to force case-insensitive matching.

Outputs:

* Matched alerts with rule name, severity, tags, and the matching line
* KPIs: total alerts, high/critical count, top rule

Operational use:

* Convert a known detection pattern into a portable rule set for quick triage.
* Test regexes against sample logs before moving them into production detection pipelines.

#### 4) Incident Timeline Builder

Use this to quickly turn mixed logs into a sortable, exportable timeline.

Inputs:

* Paste mixed log lines (auth, web, app, etc.).
* Choose timestamp interpretation:

  * Local browser time
  * Assume UTC
* Max events limit (defaults allow large pastes, but keep it reasonable for browser performance)

Outputs:

* A table with:

  * Time (best-effort extracted)
  * Severity (heuristic)
  * Tag(s) (auth_fail, traversal, sqli, probe_sensitive, etc.)
  * Raw message
* Sort oldest→newest or newest→oldest
* **Export to CSV** for sharing or report writing

---

## Description for developers (engineering / detection tooling)

### High-level architecture

* Single HTML file with CSS and vanilla JS.
* Four tabbed modules sharing utilities:

  * line splitting and HTML escaping
  * timestamp extraction (`parseIsoOrCommonTime`)
  * basic IPv4 extraction regex
* No external network requests; all logic runs locally.

### Shared utilities and parsing strategy

#### Timestamp parsing: `parseIsoOrCommonTime()`

Best-effort support for:

* ISO-8601-like timestamps (`YYYY-MM-DDTHH:MM:SSZ` or similar)
* Apache timestamps (`10/Oct/2000:13:55:36 +0000`)
* Syslog timestamps (`Jan 12 10:44:01`) with current year assumption

If no timestamp is found, it falls back to `new Date()` (important for timeline accuracy considerations).

Developer note: if you need fidelity, you should:

* require a format selection,
* support explicit year/timezone handling,
* avoid “now” fallbacks (or mark them as “unparsed time”).

---

### Module 1: Auth detector

#### Parsing: `parseAuthLine(line, mode)`

* Auto-detect selects linux/windows/generic based on keywords and structure.
* Extracts:

  * `ts` timestamp
  * `ip` (IPv4)
  * `user` (best effort)
  * `outcome` FAIL/SUCCESS
  * `service`

Linux logic keys off common sshd strings (failed/accepted/invalid user).
Windows logic keys off Event IDs **4625** (fail) and **4624** (success) in text exports.
Generic attempts `key=value` parsing (`user=`, `ip=`, `outcome=`).

Lines without clear success/fail are ignored.

#### Aggregation: `groupByWindow(events, windowMin)`

Buckets events by:

* time window (epoch / window size)
* IP

Stores counts and a small sample of raw lines.

#### Detection: `analyzeAuth()`

Generates alerts:

* BRUTE_FORCE: fails >= threshold
* PASSWORD_SPRAY: unique users >= userThreshold (with enough fails)
* SUCCESS_AFTER_FAILURES: success >= 1 and fails >= threshold/2 minimum

Ranking:

* severity first, then by numeric count derived from detail string.

Developer notes / improvements:

* The “reset on success” logic is conceptually described but not truly segmenting sequences; it primarily affects interpretation, not bucketing. If you want real burst segmentation, implement per-IP state machines with rolling windows.
* Add support for IPv6, normalized usernames, and distinguishing local vs remote auth contexts.
* Add detection for distributed spraying (many IPs → one user) and credential stuffing (web auth patterns).

---

### Module 2: Web access log scanner

#### Parsing: `parseAccessLine(line, mode)`

* Attempts to parse:

  * IP (from start of line or anywhere via regex)
  * timestamp using shared parser
  * method and path from `"METHOD PATH"`
  * status code from pattern after request quote
  * user agent as the last quoted string

Developer note: the `mode` argument exists but current parsing is “combined-ish” regardless. If you need format correctness, implement separate parsers per mode.

#### Scoring: `scoreWebEvent(e, cfg)`

Signals and weights (additive):

* traversal, SQLi markers, command injection, SSRF-ish, sensitive file probes, credential stuffing endpoints, scanner UAs, XSS markers
* HTTP status modifiers (401/403, 5xx, etc.)
* UA anomaly modifiers (empty UA or bot keywords) depending on sensitivity level

Optionally ignores 2xx responses if “focus on errors” is selected.

Outputs:

* per-event `score`, `sev`, and `hits[]`

#### Burst detection: `findBursts(events, windowSec, threshold)`

* Groups by IP, sorts by time, uses a two-pointer sliding window.
* Flags bursts when count in window >= threshold.

Developer notes / improvements:

* The “skip ahead” strategy (`i=j`) can undercount overlapping bursts; consider emitting burst intervals more carefully.
* Add URL decoding, query parameter parsing, and endpoint normalization to reduce noise.
* Support structured outputs (JSON) for downstream SIEM import.

---

### Module 3: Mini Rule Engine (YAML-lite)

#### Rules format and parser: `parseYamlLite()`

Supports only a small subset:

* list items start with `-`
* key/value pairs using `key: value`
* tags: `[a, b]` or comma-separated
* ignores comments and blank lines

It returns rules containing:

* `name`, `severity`, `match` (regex pattern string), `tags[]`

#### Execution: `runRules(rules, lines, forceI)`

* Compiles `RegExp(rule.match)` or forces `/i`.
* Tests each rule against each line (O(R * N)).
* Aggregates counts per rule for “Top rule” KPI.
* Sorts alerts by severity then rule name.

Developer notes / improvements:

* Implement safe-regex guards if you expect untrusted patterns (catastrophic backtracking risk).
* Add capture group display for context and match highlighting.
* Add “stop after N matches per rule” to control worst-case runtime.

---

### Module 4: Incident Timeline Builder

#### Build: `buildTimeline(lines, assumeUtc, max)`

* For each line:

  * parse timestamp (best effort)
  * assign tags and severity via `tagAndSeverity()`
  * store event record

#### Tagging: `tagAndSeverity(line)`

Simple indicator matching:

* auth fails/success
* sensitive probes
* traversal
* sqli markers
* server errors (5xx)
* authz (401/403)

#### Render and export

* Sort asc/desc in UI.
* Export CSV with ISO timestamps, severity, tag(s), and raw line.

Developer notes / improvements:

* Preserve original timestamps and parsing confidence (parsed vs inferred).
* Add event correlation keys (IP, user, session) to group timeline rows.
* Provide JSON export in addition to CSV.

---

## Practical positioning (what this is and is not)

* This is a **triage and analysis helper**, not a SIEM replacement.
* Detections are **heuristic** and will produce false positives/negatives depending on log quality and environment.
* It is well-suited for:

  * quick investigations,
  * training exercises,
  * portable “offline” analysis,
  * validating patterns before codifying them into SIEM rules.

---
