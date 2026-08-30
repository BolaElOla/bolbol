<img width="923" height="262" alt="image" src="https://github.com/user-attachments/assets/51f050ed-f0bc-48bc-8746-759614e4d26f" />

```
recon automation -- subs . live hosts . urls . secrets
```

`bolbol` is a single bash script that runs a full recon pipeline against a list of root domains: subdomain enumeration → live host probing → URL discovery → URL validation → focused extraction → secrets/reflection/vuln-pattern analysis. Everything that can run at the same time *does* run at the same time, with a live progress line so you're not just staring at a black terminal wondering if it's frozen.

Built for bug bounty hunters and pentesters who want one command that goes from "here's a list of domains" to "here's your keys.txt, your reflected params, and your gf candidates."

## Features

- 6-stage pipeline, fully automated from a plain domain list to final findings
- Concurrent by design: independent sources/checks launch together instead of running one after another
- Live progress line per source (falls back to clean static logs when output isn't a terminal, e.g. piped to a file or run in CI)
- `-n/--no-enum` mode for programs where the scope is the exact listed domains only (no wildcard) — skips straight to live-host probing + URL discovery
- Strict scope filtering: anything pulled in from subdomain sources or URL discovery gets checked against your input domains before it's kept
- Atomic output: the `output/` folder is only replaced once the whole run finishes successfully, so a crash mid-run never leaves you with a half-written result set
- Zero extra dependencies for the UI — no figlet/toilet, the banner is a plain string baked into the script

## How it works

| Stage | What runs | What it needs |
|---|---|---|
| 1. Passive subdomain discovery | subfinder + findomain + assetfinder, concurrently | your domain list |
| 2. Live host probing | httpx | Stage 1 output |
| 3. History + crawl | gau + katana, concurrently | Stage 2's live hosts |
| 4. GAU validation | uro (dedupe) then httpx (only gau URLs get re-probed, katana isn't) | Stage 3 output |
| 5. Focused extraction | grep against a big pattern list — JS files, param URLs, and "nice" URLs (backups, `.env`, `.git`, cloud buckets, admin panels, API docs, etc.) | Stages 3+4 merged |
| 6. Secrets + reflection + gf | mantra (JS secrets) + kxss (reflected params) + gf ssrf/sqli/lfi, all concurrently | Stage 5 output |

Pass `-n`/`--no-enum` and Stage 1 is skipped entirely — the script treats your input file as the final domain list and jumps straight to Stage 2.

## Output

Everything lands in `<script dir>/output/`, only these seven files, every run:

| File | Contents |
|---|---|
| `subs.txt` | live, in-scope hosts |
| `gf-ssrf.txt` | param URLs matching the `ssrf` gf pattern |
| `gf-sqli.txt` | param URLs matching the `sqli` gf pattern |
| `gf-lfi.txt` | param URLs matching the `lfi` gf pattern |
| `reflected.txt` | kxss output — params reflected unfiltered in the response |
| `keys.txt` | mantra output — secrets/keys found in JS |
| `nice_urls.txt` | URLs matching the "interesting" pattern list (backups, configs, git dirs, admin panels, cloud storage, API endpoints, etc.) |

## Requirements

You need Go, Rust/Cargo (or just the precompiled binary), Python/pipx, and these tools on your `$PATH`:

```
subfinder findomain assetfinder gau katana uro httpx mantra kxss gf
setsid timeout xargs awk sed grep sort
```

The last six are standard on basically any Linux box. Here's how to get the rest:

```bash
# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# tomnomnom tools
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/gf@latest

# gau (lc)
go install github.com/lc/gau/v2/cmd/gau@latest

# kxss (tomnomnom's original has no go.mod, use this maintained fork)
go install github.com/Emoe/kxss@latest

# mantra (JS secrets)
go install github.com/Brosck/mantra@latest

# findomain -- either grab a precompiled binary from its GitHub releases page
# and drop it on your $PATH, or if you have Rust/Cargo:
cargo install findomain

# uro (URL list cleanup)
pipx install uro   # or: pip install uro
```

You also need `gf` patterns for `ssrf`, `sqli`, and `lfi` installed, or the script will refuse to run:

```bash
git clone https://github.com/rix4uni/gf-patterns.git ~/.gf
gf -list   # confirm ssrf, sqli, lfi show up in here
```

Make sure everything is on `$PATH` (usually `$(go env GOPATH)/bin`, `~/.cargo/bin`, or wherever pipx installs to) before running the script — it checks for all of these up front and tells you exactly what's missing instead of failing halfway through.

## Installation

```bash
git clone https://github.com/<your-username>/bolbol.git
cd bolbol
chmod +x bolbol.sh
```

Optional: drop it somewhere on your `$PATH` so you can just type `bolbol` from anywhere:

```bash
sudo ln -s "$(pwd)/bolbol.sh" /usr/local/bin/bolbol
```

## Usage

```
bolbol [-n] <domains.txt>
```

Input file — one root domain per line, nothing else:

```
example.com
example.org
```

No scheme, no path, no port, no wildcard, no whitespace. The script validates every line and dies immediately if something doesn't look like a plain root domain.

### Options

| Flag | Meaning |
|---|---|
| `-n`, `--no-enum` | Skip subdomain enumeration entirely. Goes straight to live-host probing + gau/katana on the exact domains you gave it. Use this when a program's scope is the listed domains only, not the wildcard. |
| `-h`, `--help` | Print usage and exit |

### Example

```bash
./bolbol.sh scope.txt
```

Output always goes to `<script dir>/output/` — no flags for that, it's fixed on purpose so you always know where to look.

## A note on scope and legality

This tool is built for authorized security testing only — bug bounty programs you're enrolled in, pentests you're contracted for, or your own infrastructure. Running active recon (live host probing, crawling, URL discovery) against domains you don't have permission to test is illegal in most places. Always confirm scope before you point this at anything.

## Author

Built by **Belal Mohamed**.

[LinkedIn](https://www.linkedin.com/in/belalmohamed3690/)

## License

No license — if you want to use it mention my name
