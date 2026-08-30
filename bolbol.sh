#!/usr/bin/env bash
#
# bolbol - live recon workflow
# Usage: bolbol [-n] domains.txt
#
# Options:
#   -n, --no-enum   Skip subdomain enumeration. Use this when a program's
#                   scope is the exact listed domains only (no wildcard) --
#                   goes straight to live-host probing + gau/katana on the
#                   domains you gave it, no subfinder/findomain/assetfinder.
#   -h, --help      Print this help and exit
#
# Final output ONLY (always written to <script dir>/output):
#   output/subs.txt
#   output/gf-ssrf.txt
#   output/gf-sqli.txt
#   output/gf-lfi.txt
#   output/reflected.txt
#   output/keys.txt
#   output/nice_urls.txt
#
# Changes since 2026-08-30-v7:
#   - Stage 1 (subfinder, findomain, amass, assetfinder, crt.sh) used to run
#     one after another, each internally parallel across domains but
#     strictly sequential relative to each other. They now all launch at
#     once and run concurrently, with a live combined progress line and a
#     result line printed the moment each source finishes.
#   - gau and katana (previously two sequential stages) now launch together
#     and run concurrently too, since neither depends on the other -- both
#     only need the live-host list from Stage 2.
#   - Stage 6 (mantra, kxss, gf ssrf/sqli/lfi) used to run one after
#     another; all five are independent checks over data that's already
#     sitting on disk by then, so they now launch together too, the same
#     way Stage 1 and Stage 3 do.
#   - jsluice removed entirely (was redundant with mantra for JS secrets;
#     one less dependency, one less thing to run).
#   - All non-essential flags removed (-o/-j/-q/--no-color/-V). Output
#     always goes to <script dir>/output, parallelism is a sane fixed
#     default. Added -n/--no-enum instead: skip subdomain enum and go
#     straight to gau/katana against the exact domains you gave it, for
#     programs where the wildcard isn't in scope.
#   - New banner, no external dependency (no figlet/toolkit) -- it's a
#     plain string baked into the script.
#   - Fixed a latent bug in the per-domain worker functions (findomain_job,
#     assetfinder_job, amass_job, crt_job): `if ! cmd; then ... "$?" ...`
#     captures the *negated* exit status (bash flips $? after `!`), so
#     failure logs were reporting the wrong code, usually a false exit 0.
#     Now the real exit code is captured before any negation happens.
#   - Fixed a race in the gf pattern check: `gf -list | grep -Fxq pattern`
#     can die under `set -o pipefail` because grep -q exits the instant it
#     finds a match, SIGPIPE-ing the still-writing gf process -- pipefail
#     then reports that as a failure even though the match was found.
#     gf's output is now captured in full first, then grepped.
#   - Fixed the banner's top/bottom rule, which was built with
#     `tr ' ' '-'` (a real box-drawing dash): GNU tr cannot substitute a
#     single byte for a multi-byte UTF-8 character, in ANY locale -- it
#     was silently emitting garbage bytes on every single run. Rebuilt
#     with the same safe bash substitution box_top/box_bottom already use.
#   - Fixed column misalignment throughout the progress/result lines and
#     the final stats box: several labels used a "->"-style arrow (a
#     multi-byte character); on a system without a UTF-8 locale set
#     (common on minimal servers/containers -- exactly where this tends to
#     run unattended), bash mis-measures its width and every fixed-width
#     column after it drifts. Replaced with a plain ASCII "->" everywhere,
#     which measures correctly no matter the locale.
#   - Dependency check no longer prints a "✓ cmd" line for all ~20 required
#     tools on every single run; it now stays silent when everything is
#     present and only prints anything (the missing tool names, "✗") when
#     a dependency is actually missing.
#   - Fixed garbled/doubled result counts in the live progress lines (e.g.
#     "192 results  (00:00:02)2 results"): $CR was a plain `\r`, which only
#     moves the cursor back to column 0 and doesn't erase anything. Once a
#     source finished, its (shorter) result line was printed over the
#     (longer) live "⏱ .../N sources .../ results" line, leaving the old
#     line's tail visible past the end of the new one. $CR now also emits
#     `\033[K` (clear to end of line) before the new content is written.
#   - Amass and crt.sh removed entirely from Stage 1. Subdomain discovery
#     is now Subfinder + Findomain + Assetfinder (3 concurrent sources
#     instead of 5). curl and jq were only ever used by crt_job, so
#     they've been dropped from the dependency list along with amass.
#

set -o pipefail
shopt -s nullglob

VERSION="2026-08-30-v11"
TOTAL_STAGES=6
SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname -- "$SCRIPT_PATH")"
OUTPUT_DIR="$SCRIPT_DIR/output"
TMP_DIR=""
WARNINGS=0
NO_ENUM=0
PARALLEL_JOBS=10
START_TS="$(date +%s)"
STAGE_START_TS="$START_TS"

# ----------------------------- UI ---------------------------------
# Colors and live-updating lines only make sense on a real terminal. If
# stdout is redirected to a file we print plain, static lines instead --
# no \r overwrite tricks, no escape codes in your logs.
USE_COLOR=1
[[ -t 1 ]] || USE_COLOR=0
[[ -n "${NO_COLOR:-}" ]] && USE_COLOR=0

if (( USE_COLOR )); then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; BLUE=$'\033[34m'; CYAN=$'\033[36m'
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
    RESET=$'\033[0m'
else
    BOLD=""; DIM=""; BLUE=""; CYAN=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi
# \r alone only moves the cursor back to column 0 -- it does NOT erase
# what was already on the line. Every live-updating line in this script
# gets overwritten by a *shorter* one once a source finishes (the "⏱
# .../N sources .../ results" progress line is longer than the final
# per-source result line), so without an explicit clear-to-end-of-line
# the tail of the old line survives past the end of the new one --
# that's the doubled/garbled "192 results  (00:00:02)2 results" output.
# \033[K erases from the cursor to the end of the line; every use of
# $CR in this script is already gated behind `[[ -t 1 ]]`, so it's safe
# to bake the clear into CR itself.
CR=$'\r\033[K'

# Interior width of every box in the UI. Every border and every content line
# is generated from this ONE number, so they can never drift apart.
BOX_W=70
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    _cols="$(tput cols 2>/dev/null || echo 0)"
    if [[ "$_cols" =~ ^[0-9]+$ ]] && (( _cols > 0 )); then
        BOX_W=$(( _cols - 4 ))
        (( BOX_W > 76 )) && BOX_W=76
        (( BOX_W < 50 )) && BOX_W=50
    fi
fi

fmt_time() {
    local total=${1:-0}
    printf '%02d:%02d:%02d' $((total/3600)) $(((total%3600)/60)) $((total%60))
}

now_elapsed()   { printf '%s' "$(( $(date +%s) - START_TS ))"; }
stage_elapsed() { printf '%s' "$(( $(date +%s) - STAGE_START_TS ))"; }

log()  { printf '%s%s[%s]%s %s\n' "$BOLD" "$BLUE" '*' "$RESET" "$*"; }
ok()   { printf '%s%s[%s]%s %s\n' "$BOLD" "$GREEN" '+' "$RESET" "$*"; }
warn() { WARNINGS=$((WARNINGS+1)); printf '%s%s[%s]%s %s\n' "$BOLD" "$YELLOW" '!' "$RESET" "$*" >&2; }
die()  { printf '%s%s[%s]%s %s\n' "$BOLD" "$RED" '-' "$RESET" "$*" >&2; exit 1; }

# center_text TEXT WIDTH -> TEXT padded with spaces on both sides to WIDTH
# Length is measured with `wc -m` (locale-aware codepoint count) rather than
# bash's own ${#text}, and never byte-slices the text -- on a shell whose
# bash build lacks proper multibyte support, ${#text} on a multi-byte string
# (like the banner below) returns its *byte* length, and slicing at that
# offset can cut a UTF-8 character in half and corrupt the output. wc -m
# degrades gracefully to the same byte count in that scenario instead of
# ever mis-slicing, so worst case is "not centered", never garbled.
center_text() {
    local text="$1" width="$2" len pad left right
    len=$(printf '%s' "$text" | wc -m)
    (( len >= width )) && { printf '%s' "$text"; return; }
    pad=$(( width - len )); left=$(( pad / 2 )); right=$(( pad - left ))
    printf '%*s%s%*s' "$left" '' "$text" "$right" ''
}

# box_top/box_bottom COLOR [FILL_CHAR] [LEFT_CORNER] [RIGHT_CORNER]
# box_line COLOR TEXT  -- draws one bordered, width-correct row
box_top() {
    local color="$1" ch="${2:-─}" l="${3:-┌}" r="${4:-┐}" fill
    fill="$(printf '%*s' "$BOX_W" '')"
    printf '%s%s%s%s%s%s\n' "$BOLD" "$color" "$l" "${fill// /$ch}" "$r" "$RESET"
}
box_bottom() {
    local color="$1" ch="${2:-─}" l="${3:-└}" r="${4:-┘}" fill
    fill="$(printf '%*s' "$BOX_W" '')"
    printf '%s%s%s%s%s%s\n' "$BOLD" "$color" "$l" "${fill// /$ch}" "$r" "$RESET"
}
box_line() {
    local color="$1" text="$2"
    (( ${#text} > BOX_W )) && text="${text:0:BOX_W}"
    printf '%s%s│%-*s│%s\n' "$BOLD" "$color" "$BOX_W" "$text" "$RESET"
}

stage_banner() {
    local n="$1" label="$2"
    STAGE_START_TS="$(date +%s)"
    printf '\n'
    box_top "$CYAN"
    box_line "$CYAN" "  [$n/$TOTAL_STAGES] $label"
    box_bottom "$CYAN"
}

# Self-contained ASCII logo -- no figlet/toilet, just a string baked into
# the script, so it never becomes a new dependency.
BANNER_LINES=(
'████  ████  █     ████  ████  █      '
'█░░█░ █░░█░ █░    █░░█░ █░░█░ █░      '
'████░ █░ █░ █░    ████░ █░ █░ █░      '
'█░░█░ █░ █░ █░    █░░█░ █░ █░ █░      '
'████░ ████░ █████ ████░ ████░ █████  '
' ░░░░  ░░░░  ░░░░░ ░░░░  ░░░░  ░░░░░  '
)
print_banner() {
    local line rule
    # NB: do not build this with `tr ' ' '─'` -- GNU tr cannot substitute a
    # single byte for a multi-byte UTF-8 character in ANY locale (not just
    # C/POSIX); it silently emits the replacement's first byte repeated,
    # which corrupts stdout with invalid UTF-8 on every single run. Bash's
    # own substitution below does this correctly.
    rule="$(printf '%*s' "$BOX_W" '')"; rule="${rule// /─}"
    printf '\n%s%s%s%s\n' "$BOLD" "$GREEN" "$rule" "$RESET"
    for line in "${BANNER_LINES[@]}"; do
        printf '%s%s%s%s\n' "$BOLD" "$GREEN" "$(center_text "$line" "$BOX_W")" "$RESET"
    done
    printf '%s%s%s%s\n' "$DIM" "$GREEN" "$(center_text "recon automation -- subs . live hosts . urls . secrets" "$BOX_W")" "$RESET"
    printf '%s%s%s%s\n' "$BOLD" "$GREEN" "$rule" "$RESET"
}

usage() {
    cat <<USAGE
Usage: bolbol [-n] <domains.txt>

Input:  one root domain per line
        example.com
        example.org
No scheme, path, port, wildcard, or whitespace is accepted.

Options:
  -n, --no-enum   Skip subdomain enumeration; go straight to live-host
                  probing + gau/katana on the exact domains you gave it.
                  Use this when a program's scope isn't wildcard.
  -h, --help      Print this help and exit

Output always goes to: $SCRIPT_DIR/output
        subs.txt, gf-ssrf.txt, gf-sqli.txt, gf-lfi.txt,
        reflected.txt, keys.txt, nice_urls.txt
USAGE
}

# -------------------------- cleanup/signals ------------------------
# Every background job we launch (setsid'd, so each is its own process
# group leader) gets tracked here so Ctrl+C kills all of them, not just
# whichever one happens to be "active" -- with Stage 1 and the gau/katana
# stage now running several sources at once, there's never just one.
JOB_PIDS=()
track_job() { JOB_PIDS+=("$1"); }

kill_all_jobs() {
    local pid
    for pid in "${JOB_PIDS[@]}"; do
        [[ -n "$pid" ]] || continue
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in "${JOB_PIDS[@]}"; do
        [[ -n "$pid" ]] || continue
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    done
    JOB_PIDS=()
}

cleanup() {
    kill_all_jobs
    [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]] && rm -rf -- "$TMP_DIR"
}

terminate() {
    printf '\n%s%s[!] Interrupted after %s.%s\n' "$BOLD" "$YELLOW" "$(fmt_time "$(now_elapsed)")" "$RESET"
    trap - EXIT INT TERM HUP
    cleanup
    exit 130
}

trap cleanup EXIT
trap terminate INT TERM HUP

# ---------------------------- helpers ------------------------------
count_lines() {
    local file="$1"
    [[ -s "$file" ]] || { printf '0'; return; }
    awk 'NF {n++} END {print n+0}' "$file"
}

# count_source KIND PATH -> line count for either a single file or every
# *.txt file under a directory (used by the concurrent-source progress line)
count_source() {
    local kind="$1" path="$2" total=0 f
    if [[ "$kind" == "dir" ]]; then
        for f in "$path"/*.txt; do total=$(( total + $(count_lines "$f") )); done
        printf '%s' "$total"
    else
        count_lines "$path"
    fi
}

sort_clean() {
    local src="$1" dst="$2"
    [[ -f "$src" ]] || : > "$dst"
    LC_ALL=C sort -u "$src" | sed '/^[[:space:]]*$/d' > "$dst"
}

record_failure() {
    local label="$1" rc="$2"
    warn "$label failed (exit $rc); collected output, if any, will be kept."
    printf '%s (exit %s)\n' "$label" "$rc" >> "$FAILED_LOG"
    printf '[%s] %s -> exit %s\n' "$(date '+%F %T')" "$label" "$rc" >> "$TMP_DIR/debug.log"
}

# Single blocking command, live line count + total runtime. Falls back to a
# single start/end line (no \r redraw) when not attached to a real terminal.
run_counted() {
    local label="$1" out="$2"
    shift 2
    : > "$out"

    setsid "$@" > "$out" 2>>"$TMP_DIR/debug.log" &
    local pid=$!
    track_job "$pid"

    if [[ -t 1 ]]; then
        while kill -0 "$pid" 2>/dev/null; do
            printf '%s' "$CR"
            printf '%s⏱ %s%s  %-42s  %s%s results%s' "$CYAN" "$DIM" "$(fmt_time "$(now_elapsed)")" "$label" "$GREEN" "$(count_lines "$out")" "$RESET"
            sleep 0.5
        done
    fi

    local rc=0
    wait "$pid" || rc=$?
    [[ -t 1 ]] && printf '%s' "$CR"
    printf '    %-42s  %s%s results%s  %s(%s)%s\n' "$label" "$GREEN" "$(count_lines "$out")" "$RESET" "$DIM" "$(fmt_time "$(stage_elapsed)")" "$RESET"
    return "$rc"
}

# Command receiving file as stdin. $1 is reserved for input path.
run_counted_input() {
    local label="$1" input="$2" out="$3"
    shift 3
    : > "$out"

    setsid bash -c 'exec "${@:2}" < "$1"' _ "$input" "$@" > "$out" 2>>"$TMP_DIR/debug.log" &
    local pid=$!
    track_job "$pid"

    if [[ -t 1 ]]; then
        while kill -0 "$pid" 2>/dev/null; do
            printf '%s' "$CR"
            printf '%s⏱ %s%s  %-42s  %s%s results%s' "$CYAN" "$DIM" "$(fmt_time "$(now_elapsed)")" "$label" "$GREEN" "$(count_lines "$out")" "$RESET"
            sleep 0.5
        done
    fi

    local rc=0
    wait "$pid" || rc=$?
    [[ -t 1 ]] && printf '%s' "$CR"
    printf '    %-42s  %s%s results%s  %s(%s)%s\n' "$label" "$GREEN" "$(count_lines "$out")" "$RESET" "$DIM" "$(fmt_time "$(stage_elapsed)")" "$RESET"
    return "$rc"
}

# Turn a domain into a filesystem-safe filename so parallel workers can each
# write their own file and never interleave/corrupt each other's output.
safe_name() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
export -f safe_name

# launch_pool OUTDIR JOBFUNC JOBS -> starts JOBFUNC once per domain in
# $NORMALIZED, up to JOBS at a time, in the background, and returns
# immediately. Sets LAST_BG_PID. Must be called directly (not inside a
# command substitution) so the job stays a direct child of this shell --
# that's what lets `wait "$pid"` later retrieve its real exit status.
launch_pool() {
    local outdir="$1" jobfunc="$2" jobs="$3"
    mkdir -p -- "$outdir"
    rm -f -- "$outdir"/*.txt "$outdir"/.done_* 2>/dev/null

    setsid bash -c '
        jobfunc="$1"; outdir="$2"; jobs="$3"; infile="$4"
        xargs -P "$jobs" -I{} bash -c "\"\$0\" \"\$1\" \"\$2\"" "$jobfunc" {} "$outdir" < "$infile"
    ' _ "$jobfunc" "$outdir" "$jobs" "$NORMALIZED" &
    LAST_BG_PID=$!
    track_job "$LAST_BG_PID"
}

# await_group PID_ARR LABEL_ARR KIND_ARR PATH_ARR DONE_ARR STATUS_LABEL
# Polls every job in the group, prints a single combined live-progress line,
# and prints each source's own result line the moment it finishes (in
# whatever order they actually complete). This is what lets several sources
# run concurrently without their progress lines corrupting each other.
await_group() {
    local -n _pid=$1 _label=$2 _kind=$3 _path=$4 _done=$5
    local status_label="$6"
    local n="${#_pid[@]}" finished=0 i pid rc cnt total_lines
    (( n == 0 )) && return 0

    while (( finished < n )); do
        for i in "${!_pid[@]}"; do
            [[ "${_done[$i]}" == "1" ]] && continue
            pid="${_pid[$i]}"
            if ! kill -0 "$pid" 2>/dev/null; then
                rc=0
                wait "$pid" || rc=$?
                _done[$i]=1
                finished=$(( finished + 1 ))
                cnt="$(count_source "${_kind[$i]}" "${_path[$i]}")"
                [[ -t 1 ]] && printf '%s' "$CR"
                printf '    %-30s  %s%s results%s  %s(%s)%s\n' \
                    "${_label[$i]}" "$GREEN" "$cnt" "$RESET" "$DIM" "$(fmt_time "$(stage_elapsed)")" "$RESET"
                (( rc == 0 )) || record_failure "${_label[$i]}" "$rc"
            fi
        done
        if [[ -t 1 ]] && (( finished < n )); then
            total_lines=0
            for i in "${!_pid[@]}"; do
                total_lines=$(( total_lines + $(count_source "${_kind[$i]}" "${_path[$i]}") ))
            done
            printf '%s' "$CR"
            printf '%s⏱ %s%s  %-30s  %s%s/%s sources%s  %s%s results%s' \
                "$CYAN" "$DIM" "$(fmt_time "$(now_elapsed)")" "$status_label" \
                "$GREEN" "$finished" "$n" "$RESET" "$GREEN" "$total_lines" "$RESET"
        fi
        (( finished < n )) && sleep 0.5
    done
}

# ---- per-domain worker functions used by launch_pool ----
# Each one: writes its result to OUTDIR/<safe-domain>.txt, appends a line to
# parallel_failed.log on failure, and always drops a .done_ marker.
#
# NB: the real exit code is captured into `rc` from a plain (non-negated)
# command *before* any `if`, then tested with `(( rc != 0 ))`. Writing
# `if ! cmd; then ... "$?" ...; fi` instead is a trap: bash flips $? to
# reflect the negated condition, not cmd's actual exit status.

findomain_job() {
    local domain="$1" outdir="$2" out rc
    out="$outdir/$(safe_name "$domain").txt"
    timeout --kill-after=10s 5m findomain -t "$domain" -q > "$out" 2>>"$TMP_DIR/debug.log"
    rc=$?
    (( rc == 0 )) || printf 'Findomain [%s] -> exit %s\n' "$domain" "$rc" >> "$TMP_DIR/parallel_failed.log"
    touch "$outdir/.done_$(safe_name "$domain")"
}
export -f findomain_job

assetfinder_job() {
    local domain="$1" outdir="$2" out rc
    out="$outdir/$(safe_name "$domain").txt"
    timeout --kill-after=10s 5m assetfinder --subs-only "$domain" > "$out" 2>>"$TMP_DIR/debug.log"
    rc=$?
    (( rc == 0 )) || printf 'Assetfinder [%s] -> exit %s\n' "$domain" "$rc" >> "$TMP_DIR/parallel_failed.log"
    touch "$outdir/.done_$(safe_name "$domain")"
}
export -f assetfinder_job

# Extract only domains in the exact supplied roots/subdomains, without regex-suffix bugs.
normalize_subs_in_scope() {
    local input="$1" output="$2"
    awk -v domains="$NORMALIZED" '
    BEGIN {
        while ((getline d < domains) > 0) roots[++n]=tolower(d)
        close(domains)
    }
    {
        gsub(/\r/, "")
        gsub(/^[[:space:]]+|[[:space:]]+$/, "")
        gsub(/^\*\./, "")
        gsub(/\.$/, "")
        x=tolower($0)
        if (x !~ /^[a-z0-9.-]+$/) next
        for (i=1; i<=n; i++) {
            r=roots[i]
            if (x == r || (length(x) > length(r) && substr(x, length(x)-length(r), length(r)+1) == "." r)) {
                print x
                break
            }
        }
    }' "$input" | sort -u > "$output"
}

normalize_urls_in_scope() {
    local input="$1" output="$2"
    awk -v domains="$NORMALIZED" '
    BEGIN {
        while ((getline d < domains) > 0) roots[++n]=tolower(d)
        close(domains)
    }
    {
        gsub(/\r/, "")
        u=$0
        if (u !~ /^https?:\/\//) next
        split(u, a, "/")
        host=tolower(a[3])
        sub(/:[0-9]+$/, "", host)
        sub(/\.$/, "", host)
        for (i=1; i<=n; i++) {
            r=roots[i]
            if (host == r || (length(host) > length(r) && substr(host, length(host)-length(r), length(r)+1) == "." r)) {
                print u
                break
            }
        }
    }' "$input" | sed '/^[[:space:]]*$/d' | sort -u > "$output"
}

# ----------------------- arguments/input ---------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -n|--no-enum) NO_ENUM=1; shift ;;
        --) shift; break ;;
        -*) die "Unknown option: $1 (see --help)" ;;
        *) break ;;
    esac
done

[[ $# -eq 1 ]] || { usage; exit 1; }
INPUT_FILE="$1"
[[ -f "$INPUT_FILE" ]] || die "Input file not found: $INPUT_FILE"
[[ -r "$INPUT_FILE" ]] || die "Input file is not readable: $INPUT_FILE"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bolbol.XXXXXX")" || die "Could not create temporary directory"
export TMP_DIR
NORMALIZED="$TMP_DIR/domains.txt"

awk '{gsub(/\r$/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "") print tolower($0)}' \
    "$INPUT_FILE" > "$NORMALIZED"

[[ -s "$NORMALIZED" ]] || die "Input file contains no domains"

while IFS= read -r domain; do
    [[ "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || \
        die "Invalid root domain in input: $domain"
done < "$NORMALIZED"

# ------------------------- dependencies ----------------------------
REQUIRED_CMDS=(subfinder findomain assetfinder gau katana uro httpx
               mantra kxss gf setsid timeout xargs awk sed grep sort)
MISSING_CMDS=()
for cmd in "${REQUIRED_CMDS[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING_CMDS+=("$cmd")
done
if (( ${#MISSING_CMDS[@]} > 0 )); then
    warn "Missing $((${#MISSING_CMDS[@]})) of ${#REQUIRED_CMDS[@]} required command(s):"
    for cmd in "${MISSING_CMDS[@]}"; do
        printf '  %s✗%s %s\n' "$RED" "$RESET" "$cmd"
    done
    die "Install the missing command(s) above and re-run."
fi

# Captured in full first, then grepped -- piping straight into `grep -Fxq`
# can SIGPIPE the still-writing gf process the instant grep finds its match,
# which set -o pipefail then reports as a failure even on a real hit.
gf_patterns="$(gf -list 2>>"$TMP_DIR/debug.log")"
for pattern in ssrf sqli lfi; do
    grep -Fxq "$pattern" <<< "$gf_patterns" || die "Required gf pattern is missing: $pattern"
done

# -------------------------- output setup ---------------------------
# Old output is removed now; new output is committed only when the run completes.
rm -rf -- "$OUTPUT_DIR"
mkdir -p -- "$OUTPUT_DIR" || die "Cannot create output directory: $OUTPUT_DIR"
FINAL_DIR="$TMP_DIR/final"
mkdir -p -- "$FINAL_DIR"

# Temp files
ALL_SUBS_RAW="$TMP_DIR/all_subs_raw.txt"
ALL_SUBS="$TMP_DIR/all_subs.txt"
SCOPED_SUBS="$TMP_DIR/scoped_subs.txt"
LIVE_RAW="$TMP_DIR/live_raw.txt"
LIVE_SUBS_TMP="$TMP_DIR/subs.txt"
GAU_RAW="$TMP_DIR/gau_raw.txt"
GAU_SCOPED="$TMP_DIR/gau_scoped.txt"
KATANA_RAW="$TMP_DIR/katana_raw.txt"
KATANA_SCOPED="$TMP_DIR/katana_scoped.txt"
GAU_INPUT="$TMP_DIR/gau_probe_input.txt"
GAU_CLEAN="$TMP_DIR/gau_clean.txt"
URLS_RAW="$TMP_DIR/analysis_urls.txt"
JS="$TMP_DIR/js.txt"
PARAMS="$TMP_DIR/param_urls.txt"
FAILED_LOG="$TMP_DIR/failed.log"
: > "$FAILED_LOG"
: > "$TMP_DIR/parallel_failed.log"

# Final staging files
NICE="$FINAL_DIR/nice_urls.txt"
KEYS="$FINAL_DIR/keys.txt"
REFLECTED="$FINAL_DIR/reflected.txt"
GF_SSRF="$FINAL_DIR/gf-ssrf.txt"
GF_SQLI="$FINAL_DIR/gf-sqli.txt"
GF_LFI="$FINAL_DIR/gf-lfi.txt"
LIVE_SUBS="$FINAL_DIR/subs.txt"

: > "$ALL_SUBS_RAW"

print_banner
printf '%sInput:%s   %s\n' "$BOLD" "$RESET" "$INPUT_FILE"
printf '%sDomains:%s %s\n' "$BOLD" "$RESET" "$(count_lines "$NORMALIZED")"
printf '%sOutput:%s  %s\n' "$BOLD" "$RESET" "$OUTPUT_DIR"
(( NO_ENUM )) && printf '%sMode:%s    no-enum -- exact domains only, straight to gau/katana\n' "$BOLD" "$RESET"
printf '%sStarted:%s %s\n' "$BOLD" "$RESET" "$(date '+%F %T')"

# -------------------- 1. passive discovery -------------------------
stage_banner 1 "PASSIVE SUBDOMAIN DISCOVERY"

if (( NO_ENUM )); then
    log "Skipping subdomain enumeration (-n): using the $(count_lines "$NORMALIZED") input domain(s) as-is."
    cp -- "$NORMALIZED" "$ALL_SUBS"
else
    # All three sources launch together now instead of one after another --
    # they're independent of each other, so there's no reason to wait.
    S1_PID=(); S1_LABEL=(); S1_KIND=(); S1_PATH=(); S1_DONE=()

    SUBFINDER="$TMP_DIR/subfinder.txt"; : > "$SUBFINDER"
    setsid timeout --kill-after=10s 15m subfinder -all -silent -dL "$NORMALIZED" \
        > "$SUBFINDER" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S1_PID+=("$LAST_BG_PID"); S1_LABEL+=("Subfinder [all roots]"); S1_KIND+=("file"); S1_PATH+=("$SUBFINDER"); S1_DONE+=("0")

    FINDOMAIN_DIR="$TMP_DIR/findomain_out"
    launch_pool "$FINDOMAIN_DIR" findomain_job "$PARALLEL_JOBS"
    S1_PID+=("$LAST_BG_PID"); S1_LABEL+=("Findomain [${PARALLEL_JOBS}x]"); S1_KIND+=("dir"); S1_PATH+=("$FINDOMAIN_DIR"); S1_DONE+=("0")

    ASSET_DIR="$TMP_DIR/assetfinder_out"
    launch_pool "$ASSET_DIR" assetfinder_job "$PARALLEL_JOBS"
    S1_PID+=("$LAST_BG_PID"); S1_LABEL+=("Assetfinder [${PARALLEL_JOBS}x]"); S1_KIND+=("dir"); S1_PATH+=("$ASSET_DIR"); S1_DONE+=("0")

    await_group S1_PID S1_LABEL S1_KIND S1_PATH S1_DONE "Stage 1: 3 sources"

    cat "$SUBFINDER" "$FINDOMAIN_DIR"/*.txt "$ASSET_DIR"/*.txt \
        >> "$ALL_SUBS_RAW" 2>/dev/null

    if [[ -s "$TMP_DIR/parallel_failed.log" ]]; then
        WARNINGS=$(( WARNINGS + $(count_lines "$TMP_DIR/parallel_failed.log") ))
        cat "$TMP_DIR/parallel_failed.log" >> "$FAILED_LOG"
    fi

    normalize_subs_in_scope "$ALL_SUBS_RAW" "$SCOPED_SUBS"
    cat "$NORMALIZED" "$SCOPED_SUBS" | sort -u > "$ALL_SUBS"
fi
SUB_COUNT="$(count_lines "$ALL_SUBS")"
ok "Stage 1/$TOTAL_STAGES complete  •  $SUB_COUNT unique in-scope names  •  $(fmt_time "$(stage_elapsed)")"

# ------------------------- 2. live hosts ----------------------------
stage_banner 2 "LIVE HOST PROBING"
: > "$LIVE_RAW"
if [[ -s "$ALL_SUBS" ]]; then
    if run_counted_input "httpx -> live hosts" "$ALL_SUBS" "$LIVE_RAW" \
        httpx -silent -mc 200,201,204,301,302,307,308,400,401,403,405,500 \
        -threads 50 -rate-limit 150 -timeout 10; then
        :
    else
        rc=$?
        record_failure "httpx live host probing" "$rc"
    fi
fi
sort_clean "$LIVE_RAW" "$LIVE_SUBS_TMP"
LIVE_COUNT="$(count_lines "$LIVE_SUBS_TMP")"
cp -- "$LIVE_SUBS_TMP" "$LIVE_SUBS"
ok "Stage 2/$TOTAL_STAGES complete  •  $LIVE_COUNT live URLs  •  $(fmt_time "$(stage_elapsed)")"

# --------------------- 3. gau + katana (concurrent) ------------------
# Neither depends on the other -- both only need live hosts from Stage 2 --
# so they now run side by side instead of back to back.
stage_banner 3 "GAU HISTORY + KATANA CRAWL (LIVE HOSTS ONLY, CONCURRENT)"
: > "$GAU_RAW"; : > "$KATANA_RAW"
if [[ -s "$LIVE_SUBS_TMP" ]]; then
    S2_PID=(); S2_LABEL=(); S2_KIND=(); S2_PATH=(); S2_DONE=()

    setsid bash -c 'exec "${@:2}" < "$1"' _ "$LIVE_SUBS_TMP" \
        gau --threads 50 --retries 3 --timeout 30 \
        --providers wayback,otx,urlscan \
        --blacklist png,jpg,jpeg,gif,svg,ico,bmp,webp,css,woff,woff2,ttf,eot,otf,mp4,mp3,webm,avi,mov \
        > "$GAU_RAW" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S2_PID+=("$LAST_BG_PID"); S2_LABEL+=("gau -> historical URLs"); S2_KIND+=("file"); S2_PATH+=("$GAU_RAW"); S2_DONE+=("0")

    setsid bash -c 'exec "${@:2}" < "$1"' _ "$LIVE_SUBS_TMP" \
        katana -jc -c 50 -p 20 -rl 300 -timeout 5 -retry 0 -fs rdn -silent \
        > "$KATANA_RAW" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S2_PID+=("$LAST_BG_PID"); S2_LABEL+=("katana -> live crawl"); S2_KIND+=("file"); S2_PATH+=("$KATANA_RAW"); S2_DONE+=("0")

    await_group S2_PID S2_LABEL S2_KIND S2_PATH S2_DONE "Stage 3: gau + katana"
fi
normalize_urls_in_scope "$GAU_RAW" "$GAU_SCOPED"
normalize_urls_in_scope "$KATANA_RAW" "$KATANA_SCOPED"
ok "Stage 3/$TOTAL_STAGES complete  •  gau: $(count_lines "$GAU_SCOPED")  •  katana: $(count_lines "$KATANA_SCOPED")  •  $(fmt_time "$(stage_elapsed)")"

# ---------------------- 4. GAU validation ---------------------------
stage_banner 4 "VALIDATE GAU URLS ONLY (KATANA IS NOT RE-PROBED)"
: > "$GAU_CLEAN"
if [[ -s "$GAU_SCOPED" ]]; then
    sort -u "$GAU_SCOPED" | uro 2>>"$TMP_DIR/debug.log" | sort -u > "$GAU_INPUT" || true
    if [[ -s "$GAU_INPUT" ]]; then
        if run_counted_input "httpx -> GAU URLs only" "$GAU_INPUT" "$GAU_CLEAN" \
            httpx -silent -mc 200,201,204,301,302,307,308,400,401,403,405,500 \
            -threads 50 -rate-limit 150 -timeout 10; then
            :
        else
            rc=$?
            record_failure "httpx GAU validation" "$rc"
        fi
    fi
fi
sort_clean "$GAU_CLEAN" "$GAU_CLEAN.tmp" && mv -f -- "$GAU_CLEAN.tmp" "$GAU_CLEAN"
ok "Stage 4/$TOTAL_STAGES complete  •  $(count_lines "$GAU_CLEAN") responding GAU URLs  •  $(fmt_time "$(stage_elapsed)")"

# Merge only: GAU validated URLs + Katana-discovered URLs. NO second httpx on Katana.
cat "$GAU_CLEAN" "$KATANA_SCOPED" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u | uro 2>>"$TMP_DIR/debug.log" | sort -u > "$URLS_RAW" || true
ANALYSIS_COUNT="$(count_lines "$URLS_RAW")"

# --------------------- 5. focused extraction -----------------------
stage_banner 5 "FOCUSED URL EXTRACTION"
grep -aE '^[^?]*\.js(\?|$)' "$URLS_RAW" | sort -u > "$JS" || true
grep -a '\?' "$URLS_RAW" | sort -u > "$PARAMS" || true

cat > "$TMP_DIR/nice.pattern" <<'REGEX'
\.(env|bak|bkf|bkp|txt|bok|backup|old|orig|save|swp|swo|conf|config|cfg|cnf|ini|ya?ml|log|sql|sqlite3?|db|mdb|dat|pem|key|crt|cer|csr|p12|pfx|jks|keystore|pwd|passwd|htpasswd|htaccess|ds_store|zip|gz|tgz|tar(\.gz)?|rar|7z|swf|exe|dll|jar|war|class|axd|asmx|ascx|cgi|cfm|action|pl|reg|rdp|pcf|ica|inf|nsf|ora|pac|wml|xsd|tpl|lst|npmrc|netrc|pypirc|dockercfg|mobileprovision|plist|skr|pgp|csv|xls|xlsx|tfstate|ovpn|kdbx|pcap|pdf|docx?|pptx?|odt|ods|odp|rtf)(\?|$)|(^|/)(\.git|\.svn|\.hg|\.gitattributes|\.gitconfig|\.gitmodules|\.gitignore|\.git-rewrite)(/|$)|\b(id_rsa|id_dsa|id_ecdsa|id_ed25519|known_hosts|authorized_keys|\.bash_history|\.zsh_history|\.aws/credentials|\.git-credentials|wp-config\.php|config\.php|settings\.py|\.ssh/|kubeconfig|\.kube/config|postman_collection\.json|vault\.yml|\.vault_pass|master\.key|credentials\.yml\.enc|service_account\.json)|\bshadow\b|\b(phpmyadmin|adminer|dbadmin|cpanel|webmin|plesk|grafana|kibana|jenkins|portainer|pgadmin|_profiler|_ignition|debugbar)\b|\b(pma|horizon|telescope)\b|(actuator|heapdump|threaddump|jolokia|phpinfo|server-status|server-info|elmah\.axd|trace\.axd|_catalog|/metrics|/_search|/_cat/)|(/api/|/v[0-9]+/|/rest/|graphql|graphiql|swagger|openapi|api-docs)|(s3[.-][a-z0-9.-]*amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|firebaseio\.com|firebasestorage\.googleapis\.com|digitaloceanspaces\.com|r2\.cloudflarestorage\.com)|(Dockerfile|docker-compose\.ya?ml|\.github/workflows|Jenkinsfile|\.travis\.yml|\.circleci|composer\.(json|lock)|package(-lock)?\.json|Gemfile(\.lock)?|requirements\.txt|Pipfile)|\b(qa|uat|cms|jwt|pwd|temp|alpha|beta)[0-9]*\b|\bauth([^o]|$)|\bcert([^a]|$)|\b(private|backup|(db|database)[_-]?backup|password|passwd|cred|email|token|secret|hidden|internal|intranet|confidential|restricted|old|setup|install|dump|authentic|admin|superadmin|superuser|root|moderator|manage|backend|console|stage|sandbox|preprod|oauth|vault|keystore|api[_-]?key|access[_-]?key|client[_-]?id|client[_-]?secret|(access|refresh|id|xsrf)[_-]?token|pub(lic)?[_-]?key|export|archive|legacy|deprecated|unused|billing|payment|invoice|bank[_-]?account|migrat|seed|error[_-]?log|file[_-]?manager|upload|download|logs)|\.(js|css)\.map(\?|$)
REGEX

grep -aEi -f "$TMP_DIR/nice.pattern" "$URLS_RAW" | sort -u > "$NICE" || true

ok "Stage 5/$TOTAL_STAGES complete  •  URLs: $ANALYSIS_COUNT  •  JS: $(count_lines "$JS")  •  params: $(count_lines "$PARAMS")  •  nice: $(count_lines "$NICE")  •  $(fmt_time "$(stage_elapsed)")"

# ------------------------ 6. analysis -------------------------------
stage_banner 6 "SECRETS + REFLECTION + GF CANDIDATE ANALYSIS"
: > "$KEYS" "$REFLECTED" "$GF_SSRF" "$GF_SQLI" "$GF_LFI"

# mantra (reads $JS) and kxss/gf-ssrf/gf-sqli/gf-lfi (all read $PARAMS) are
# five completely independent checks -- same deal as Stage 1 and Stage 3,
# so they all launch together instead of running one after another.
S3_PID=(); S3_LABEL=(); S3_KIND=(); S3_PATH=(); S3_DONE=()

MANTRA_OUT="$TMP_DIR/mantra.txt"; : > "$MANTRA_OUT"
if [[ -s "$JS" ]]; then
    setsid bash -c 'exec "${@:2}" < "$1"' _ "$JS" mantra \
        > "$MANTRA_OUT" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S3_PID+=("$LAST_BG_PID"); S3_LABEL+=("Mantra -> JS secrets"); S3_KIND+=("file"); S3_PATH+=("$MANTRA_OUT"); S3_DONE+=("0")
fi

if [[ -s "$PARAMS" ]]; then
    setsid bash -c 'exec "${@:2}" < "$1"' _ "$PARAMS" kxss \
        > "$REFLECTED" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S3_PID+=("$LAST_BG_PID"); S3_LABEL+=("kxss -> reflection candidates"); S3_KIND+=("file"); S3_PATH+=("$REFLECTED"); S3_DONE+=("0")

    setsid bash -c 'exec "${@:2}" < "$1"' _ "$PARAMS" gf ssrf \
        > "$GF_SSRF" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S3_PID+=("$LAST_BG_PID"); S3_LABEL+=("gf ssrf -> candidates"); S3_KIND+=("file"); S3_PATH+=("$GF_SSRF"); S3_DONE+=("0")

    setsid bash -c 'exec "${@:2}" < "$1"' _ "$PARAMS" gf sqli \
        > "$GF_SQLI" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S3_PID+=("$LAST_BG_PID"); S3_LABEL+=("gf sqli -> candidates"); S3_KIND+=("file"); S3_PATH+=("$GF_SQLI"); S3_DONE+=("0")

    setsid bash -c 'exec "${@:2}" < "$1"' _ "$PARAMS" gf lfi \
        > "$GF_LFI" 2>>"$TMP_DIR/debug.log" &
    LAST_BG_PID=$!; track_job "$LAST_BG_PID"
    S3_PID+=("$LAST_BG_PID"); S3_LABEL+=("gf lfi -> candidates"); S3_KIND+=("file"); S3_PATH+=("$GF_LFI"); S3_DONE+=("0")
fi

await_group S3_PID S3_LABEL S3_KIND S3_PATH S3_DONE "Stage 6: 5 checks"
cat "$MANTRA_OUT" >> "$KEYS"

for f in "$KEYS" "$REFLECTED" "$GF_SSRF" "$GF_SQLI" "$GF_LFI" "$NICE" "$LIVE_SUBS"; do
    sort_clean "$f" "$f.tmp" && mv -f -- "$f.tmp" "$f"
done

ok "Stage 6/$TOTAL_STAGES complete  •  keys: $(count_lines "$KEYS")  •  reflection: $(count_lines "$REFLECTED")  •  GF: $(( $(count_lines "$GF_SSRF") + $(count_lines "$GF_SQLI") + $(count_lines "$GF_LFI") ))  •  $(fmt_time "$(stage_elapsed)")"

# ----------------------- final validation ---------------------------
EXPECTED=(subs.txt gf-ssrf.txt gf-sqli.txt gf-lfi.txt reflected.txt keys.txt nice_urls.txt)
for name in "${EXPECTED[@]}"; do
    [[ -f "$FINAL_DIR/$name" ]] || : > "$FINAL_DIR/$name"
done

# Final output directory is a commit point: only the seven final files become visible.
rm -rf -- "$OUTPUT_DIR"
mkdir -p -- "$OUTPUT_DIR"
for name in "${EXPECTED[@]}"; do
    mv -- "$FINAL_DIR/$name" "$OUTPUT_DIR/$name"
done

# ------------------------ final stats -------------------------------
TOTAL_ELAPSED="$(now_elapsed)"
printf '\n'
box_top "$GREEN" '═' '╔' '╗'
box_line "$GREEN" "$(center_text 'FINAL STATS' "$BOX_W")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Input domains' "$(count_lines "$NORMALIZED")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Unique in-scope subdomains' "$(count_lines "$ALL_SUBS")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Live URLs -> subs.txt' "$(count_lines "$OUTPUT_DIR/subs.txt")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'GAU historical URLs' "$(count_lines "$GAU_SCOPED")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'GAU URLs validated by httpx' "$(count_lines "$GAU_CLEAN")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Katana URLs (no re-probe)' "$(count_lines "$KATANA_SCOPED")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Analysis URLs (GAU + Katana)' "$(count_lines "$URLS_RAW")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'JavaScript URLs' "$(count_lines "$JS")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Parameter URLs' "$(count_lines "$PARAMS")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Keys / secrets findings' "$(count_lines "$OUTPUT_DIR/keys.txt")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Reflection findings' "$(count_lines "$OUTPUT_DIR/reflected.txt")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Nice URLs' "$(count_lines "$OUTPUT_DIR/nice_urls.txt")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'GF SSRF candidates' "$(count_lines "$OUTPUT_DIR/gf-ssrf.txt")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'GF SQLi candidates' "$(count_lines "$OUTPUT_DIR/gf-sqli.txt")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'GF LFI candidates' "$(count_lines "$OUTPUT_DIR/gf-lfi.txt")")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Warnings' "$WARNINGS")"
box_line "$GREEN" "  $(printf '%-34s %s' 'Total runtime' "$(fmt_time "$TOTAL_ELAPSED")")"
box_bottom "$GREEN" '═' '╚' '╝'

if [[ -s "$FAILED_LOG" ]]; then
    printf '\n%s%sFailed steps (%s) — check %s/debug.log while it still exists:%s\n' \
        "$BOLD" "$YELLOW" "$(count_lines "$FAILED_LOG")" "$TMP_DIR" "$RESET"
    while IFS= read -r line; do printf '  - %s\n' "$line"; done < "$FAILED_LOG"
fi

printf '%sOutput:%s %s\n' "$BOLD" "$RESET" "$OUTPUT_DIR"
printf '%sVersion:%s %s\n' "$BOLD" "$RESET" "$VERSION"
printf '%s%sDone.%s\n' "$BOLD" "$GREEN" "$RESET"
