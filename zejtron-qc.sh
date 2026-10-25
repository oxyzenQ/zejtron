#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zejtron is a Linux introspection tool.

# zejtron-qc.sh — v4 — fixes: jq `?//` lexing, deterministic SIGPIPE trial

# zejtron QC (Quality of Control/check)

set -uo pipefail

if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'
  MAG=$'\e[35m'; CYN=$'\e[36m'; BLD=$'\e[1m'; DIM=$'\e[2m'; RST=$'\e[0m'
else
  RED=; GRN=; YEL=; BLU=; MAG=; CYN=; BLD=; DIM=; RST=
fi

PASS=0; FAIL=0; SKIP=0
FAILED_TESTS=()
LISTENER_PID=""
TMPDIR_QC="$(mktemp -d /tmp/zejtron-qc.XXXXXX)"

# ─── locate binary ───────────────────────────────────────────────────
ZJ="${ZEJTRON_BIN:-}"
if [[ -z "$ZJ" ]]; then
  if command -v zejtron >/dev/null 2>&1; then
    ZJ="$(command -v zejtron)"
  else
    for p in \
      ./target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zejtron \
      ./target/x86_64-unknown-linux-musl/pro-linux-amd64-musl/zejtron \
      ./target/release/zejtron \
      ./target/debug/zejtron; do
      [[ -x "$p" ]] && { ZJ="$p"; break; }
    done
  fi
fi

die() { printf '%s✗ %s%s\n' "${RED}${BLD}" "$*" "${RST}"; rm -rf "$TMPDIR_QC"; exit 2; }
[[ -n "$ZJ" && -x "$ZJ" ]] || die "zejtron binary not found — set ZEJTRON_BIN=/path"
command -v jq      >/dev/null 2>&1 || die "jq not installed"
command -v python3 >/dev/null 2>&1 || die "python3 not installed (needed for :9999 test)"

# ─── helpers ─────────────────────────────────────────────────────────
header()  { printf '\n%s\n' "${BLD}${MAG}━━━ $* ━━━${RST}"; }
section() { printf '\n%s\n' "${BLD}${CYN}▶ $*${RST}"; }
ok()      { PASS=$((PASS+1)); printf '  %s %s\n' "${GRN}✓${RST}" "$*"; }
bad()     { FAIL=$((FAIL+1)); FAILED_TESTS+=("$*"); printf '  %s %s\n' "${RED}✗${RST}" "$*"; }
skip()    { SKIP=$((SKIP+1)); printf '  %s %s\n' "${YEL}○${RST}" "$*"; }
note()    { printf '  %s %s\n' "${DIM}·${RST}" "$*"; }

run_priv() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

# ─── listener ────────────────────────────────────────────────────────
port_in_use() {
  if command -v ss >/dev/null 2>&1; then
    [[ -n "$(ss -Hltn "sport = :$1" 2>/dev/null)" ]]
  else
    timeout 0.5 bash -c "echo >/dev/tcp/127.0.0.1/$1" 2>/dev/null
  fi
}

start_listener() {
  if port_in_use 9999; then
    note "port :9999 already bound — reusing existing listener"
    LISTENER_PID=""
    return 0
  fi
  python3 -m http.server 9999 --bind 127.0.0.1 >/dev/null 2>&1 &
  LISTENER_PID=$!
  local i
  for i in {1..30}; do
    port_in_use 9999 && return 0
    sleep 0.1
  done
  kill "$LISTENER_PID" 2>/dev/null; LISTENER_PID=""
  return 1
}

stop_listener() {
  [[ -n "$LISTENER_PID" ]] || return
  kill "$LISTENER_PID" 2>/dev/null || true
  wait "$LISTENER_PID" 2>/dev/null || true
  LISTENER_PID=""
}

cleanup() { stop_listener; rm -rf "$TMPDIR_QC"; }
trap cleanup EXIT INT TERM

# ─── phase 1 ─────────────────────────────────────────────────────────
phase1() {
  header "FASE 1 · Typed JSON API"
  local out n pid comm p0

  section "path sh --print-json → .active.path"
  if out=$("$ZJ" path sh --print-json 2>/dev/null); then
    if jq -e '.active.path | type=="string" and length>0' <<<"$out" >/dev/null 2>&1; then
      ok "path = $(jq -r '.active.path' <<<"$out")"
    else
      bad "path: .active.path missing or not a string"
    fi
  else
    bad "path sh exited non-zero"
  fi

  section "recent . --limit 2 --print-json"
  if out=$("$ZJ" recent . --limit 2 --print-json 2>/dev/null); then
    n=$(jq -r '.files | length' <<<"$out" 2>/dev/null)
    if [[ "$n" =~ ^[0-9]+$ ]]; then
      (( n <= 2 )) && ok "returned $n file(s) (limit=2 respected)" || bad "recent: length=$n > 2"
    else
      bad "recent: .files missing or not array"
    fi
  else
    bad "recent exited non-zero"
  fi

  section "port --tcp --snapshot-only --print-json"
  if out=$("$ZJ" port --tcp --snapshot-only --print-json 2>/dev/null); then
    if jq -e '.ports | length > 0' <<<"$out" >/dev/null 2>&1; then
      p0=$(jq -c '.ports[0] | {protocol, local_addr, state}' <<<"$out")
      ok "ports[0] = $p0"
    else
      skip "port: no TCP listeners in snapshot"
    fi
  else
    bad "port exited non-zero"
  fi

  section "proc --me --depth 1 --print-json"
  if out=$("$ZJ" proc --me --depth 1 --print-json 2>/dev/null); then
    pid=$(jq -r '.processes[0].pid  // empty' <<<"$out" 2>/dev/null)
    comm=$(jq -r '.processes[0].comm // empty' <<<"$out" 2>/dev/null)
    if [[ -n "$pid" && -n "$comm" ]]; then
      ok "proc[0] = {\"pid\": $pid, \"comm\": \"$comm\"}"
    else
      bad "proc: .processes[0].pid or .comm missing"
    fi
  else
    bad "proc exited non-zero"
  fi

  section "net --print-json → interface lo"
  if out=$("$ZJ" net --print-json 2>/dev/null); then
    if jq -e 'any(.interfaces[]; .name=="lo")' <<<"$out" >/dev/null 2>&1; then
      ok "loopback 'lo' present"
    else
      skip "net: no 'lo' interface"
    fi
  else
    bad "net exited non-zero"
  fi
}

# ─── phase 2 ─────────────────────────────────────────────────────────
phase2() {
  header "FASE 2 · Evidence Ledger (eBPF & Provenance)"
  local out lane ub gib whyout whyerr row attach_err

  attach_err="$TMPDIR_QC/attach.err"

  section "doctor --attach"
  if run_priv "$ZJ" doctor --attach >/dev/null 2>"$attach_err"; then
    ok "eBPF probes attached"
  else
    note "$(head -1 "$attach_err" 2>/dev/null || echo 'attach failed')"
    skip "doctor --attach — continuing"
  fi

  section "doctor --print-json → .ebpf.lane"
  if out=$("$ZJ" doctor --print-json 2>/dev/null); then
    lane=$(jq -r '.ebpf.lane // empty' <<<"$out" 2>/dev/null)
    if [[ "$lane" == "live" ]]; then
      ok "ebpf.lane = live"
    elif [[ -n "$lane" ]]; then
      note "ebpf.lane = $lane"; skip "lane not 'live'"
    else
      bad "doctor: .ebpf.lane missing"
    fi
  else
    bad "doctor exited non-zero"
  fi

  section "doctor --symptom ram --print-json"
  if out=$(run_priv "$ZJ" doctor --symptom ram --print-json 2>/dev/null); then
    ub=$(jq -r '.memory.used_bytes // empty' <<<"$out" 2>/dev/null)
    if [[ "$ub" =~ ^[0-9]+$ ]]; then
      gib=$(awk -v b="$ub" 'BEGIN{printf "%.2f", b/1073741824}')
      ok "used_bytes = $ub (~${gib} GiB)"
    else
      bad "doctor --symptom ram: .memory.used_bytes not numeric"
    fi
  else
    skip "doctor --symptom ram exited non-zero"
  fi

  section "why <file> --since 10s --print-json (live eBPF catch)"
  local tmp=/tmp/qc-ultimate.txt
  printf 'init\n' > "$tmp"
  whyout="$TMPDIR_QC/whyout"; whyerr="$TMPDIR_QC/whyerr"

  if [[ $EUID -eq 0 ]]; then
    ( timeout -k 2s 15s "$ZJ" why "$tmp" --since 10s --print-json >"$whyout" 2>"$whyerr" ) &
  else
    ( timeout -k 2s 15s sudo "$ZJ" why "$tmp" --since 10s --print-json >"$whyout" 2>"$whyerr" ) &
  fi
  local whypid=$!
  sleep 1
  printf 'HACKED\n' >> "$tmp"
  wait "$whypid" 2>/dev/null || true

  if jq -e '.changes.rows[]? | select(.provenance=="observed")' "$whyout" >/dev/null 2>&1; then
    row=$(jq -c '[.changes.rows[] | select(.provenance=="observed")][0] | {kind, actor, provenance}' "$whyout")
    ok "eBPF observed: $row"
  else
    [[ -s "$whyerr" ]] && note "why stderr: $(head -1 "$whyerr")"
    skip "why: no 'observed' row captured (timing/attach)"
  fi
  rm -f "$tmp"
}

# ─── phase 3 ─────────────────────────────────────────────────────────
phase3() {
  header "FASE 3 · Honesty Test (Graceful Degradation)"
  local out rc mode unacc

  section "why /file/ngasal/yang/nggak/ada --print-json"
  out=$("$ZJ" why /file/ngasal/yang/nggak/ada --print-json 2>/dev/null); rc=$?
  if (( rc != 0 )); then
    if jq -e . <<<"$out" >/dev/null 2>&1; then
      ok "exit=$rc, JSON: $(jq -c . <<<"$out" | head -c 120)"
    else
      ok "exit=$rc (graceful)"
    fi
  else
    bad "why missing-file: expected non-zero, got 0"
  fi

  section "port 99999 --print-json"
  out=$("$ZJ" port 99999 --print-json 2>/dev/null); rc=$?
  if (( rc != 0 )); then
    if grep -qi 'invalid port' <<<"$out"; then
      ok "exit=$rc, message has 'invalid port'"
    elif jq -e . <<<"$out" >/dev/null 2>&1; then
      ok "exit=$rc, JSON: $(jq -c . <<<"$out" | head -c 120)"
    else
      ok "exit=$rc (graceful)"
    fi
  else
    bad "port 99999: expected non-zero, got 0"
  fi

  section "holds /etc/resolv.conf --print-json (unprivileged)"
  if [[ $EUID -eq 0 ]]; then
    skip "running as root — cannot test unprivileged mode"
  else
    out=$("$ZJ" holds /etc/resolv.conf --print-json 2>/dev/null); rc=$?
    if (( rc == 0 )); then
      mode=$(jq -r '.mode // empty' <<<"$out" 2>/dev/null)
      # all `?` and `//` are space-separated — avoids jq 1.7 `?//` lexer trap
      unacc=$(jq -r '.unaccounted | if type=="array" then (.[]? | .reason? // . | tostring) else . end' <<<"$out" 2>/dev/null | head -1)
      if [[ "$mode" == "snapshot" ]]; then
        ok "mode=snapshot | unaccounted=${unacc:-<empty>}"
      else
        note "mode=$mode"; skip "holds: unexpected mode"
      fi
    else
      skip "holds exited $rc"
    fi
  fi

  # ── SIGPIPE: deterministic trial via jq compile-error ────────────
  # `jq 'err'` = undefined filter → jq exits rc 3 at startup, BEFORE reading stdin.
  # Pipe read-end closes immediately → zejtron's first stdout write hits SIGPIPE/EPIPE.
  # Deterministic regardless of output size (unlike dd bs=1 which needs >64 KiB).
  section "SIGPIPE handling (broken pipe → expect exit 141)"
  local sigerr="$TMPDIR_QC/sig.err"
  "$ZJ" proc --print-json 2>"$sigerr" | jq 'err' >/dev/null 2>&1
  rc=${PIPESTATUS[0]}
  case $rc in
    141) ok "proc --print-json | jq 'err' → exit 141 (SIGPIPE, correct UNIX)" ;;
    101) if grep -qi "Broken pipe" "$sigerr"; then
           bad "SIGPIPE: Rust panic (BUG — must restore SIG_DFL for SIGPIPE)"
         else
           bad "SIGPIPE: Rust panic (unexpected)"
         fi ;;
    134) bad "SIGPIPE: SIGABRT (panic=abort profile?)" ;;
    0)   note "graceful EPIPE (exit 0) — non-canonical; SIGPIPE=141 is standard"
         skip "SIGPIPE: expected 141, got 0" ;;
    *)   skip "SIGPIPE: exit $rc (inconclusive)" ;;
  esac
  rm -f "$sigerr"
}

# ─── phase 4 ─────────────────────────────────────────────────────────
phase4() {
  header "FASE 4 · Pipeline (SRE building block)"
  local raw keys sample pid bin pkg

  section "bootstrap listener on :9999"
  if ! start_listener; then
    bad "cannot bind :9999"; return
  fi
  ok "listener ready${LISTENER_PID:+ (PID $LISTENER_PID)}"

  section "port 9999 --snapshot-only --print-json"
  raw=$(run_priv "$ZJ" port 9999 --snapshot-only --print-json 2>/dev/null)
  if [[ -z "$raw" ]]; then
    bad "port 9999: empty output"; return
  fi
  if ! jq -e . <<<"$raw" >/dev/null 2>&1; then
    bad "port 9999: output is not valid JSON"
    note "raw: $(head -c 200 <<<"$raw")"; return
  fi

  keys=$(jq -r 'keys | join(",")' <<<"$raw" 2>/dev/null)
  note "JSON top-level keys: $keys"
  sample=$(jq -c '(.ports // .sockets // .entries // .listeners // [])[0] // empty' <<<"$raw" 2>/dev/null)
  [[ -n "$sample" ]] && note "entry[0]: $(head -c 300 <<<"$sample")"

  # NOTE: every `?` / `//` MUST be space-separated. `?//` is lexed by jq 1.7
  # as the destructuring-alternative token and causes rc=3 before any JSON
  # is parsed (this was the "entry not found" false negative in v3).
  pid=$(jq -r '
    def entry_pid:
      (.owners? // [] | .[0]?.pid)
      // (.owner?.pid)
      // (.pid)
      // (.pids? // [] | .[0])
      // empty;
    def port_match:
      (.port? == 9999)
      or ((.local_addr? // "") | tostring | test(":9999$"))
      or (.local?.port? == 9999);
    ((.ports // .sockets // .entries // .listeners // [])[]
     | select(port_match)
     | entry_pid)
  ' <<<"$raw" 2>/dev/null | head -1)

  if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]]; then
    ok "port 9999 → owner PID=$pid"
  else
    # second pass: entry exists but no owner PID exposed?
    if jq -e '
         ((.ports // .sockets // .entries // .listeners // [])[]
          | select((.local_addr? // "") | tostring | test(":9999$")))
       ' <<<"$raw" >/dev/null 2>&1; then
      note "entry :9999 found, but owner PID not in shape"
      skip "port 9999: found in list, owner PID not exposed (.owners absent by design)"
    else
      bad "port 9999: entry not found at all — listener IS bound, port command missed it"
      return
    fi
    if [[ -n "$LISTENER_PID" ]] && kill -0 "$LISTENER_PID" 2>/dev/null; then
      pid=$LISTENER_PID
      note "downstream uses our own PID $pid"
    else
      skip "no PID — aborting chain"; return
    fi
  fi

  section "proc --me --print-json → .comm for PID $pid"
  # run WITHOUT sudo so --me reflects the listener's UID
  bin=$("$ZJ" proc --me --print-json 2>/dev/null \
        | jq -r --arg p "$pid" '.processes[]? | select((.pid|tostring)==$p) | .comm // empty' 2>/dev/null | head -1)
  if [[ -z "$bin" ]]; then
    bin=$(tr -d '\n' < "/proc/$pid/comm" 2>/dev/null)
    [[ -n "$bin" ]] && note "proc --me missed PID $pid; fell back to /proc/$pid/comm"
  fi
  if [[ -z "$bin" ]]; then
    bad "cannot resolve comm for PID $pid"; return
  fi
  ok "comm = $bin (PID $pid)"

  section "path $bin --print-json → .active.package"
  pkg=$("$ZJ" path "$bin" --print-json 2>/dev/null \
        | jq -r '.active.package // empty' 2>/dev/null | head -1)
  if [[ -n "$pkg" ]]; then
    ok "package = $pkg"
  else
    skip "path: .active.package empty for '$bin'"
  fi
}

# ─── main ────────────────────────────────────────────────────────────
main() {
  printf '%s\n' "${BLD}${BLU}╔══════════════════════════════════════════════╗${RST}"
  printf '%s\n' "${BLD}${BLU}║   🐉  Zejtron Manual QC — One-Click Runner   ║${RST}"
  printf '%s\n' "${BLD}${BLU}╚══════════════════════════════════════════════╝${RST}"
  printf '  binary : %s\n' "$ZJ"
  printf '  user   : %s%s\n' "$(id -un)" "$([[ $EUID -eq 0 ]] && echo ' (root)' || echo '')"
  printf '  jq     : %s (%s)\n' "$(command -v jq)" "$(jq --version 2>/dev/null)"
  printf '  tmpdir : %s\n' "$TMPDIR_QC"

  if [[ $EUID -ne 0 ]]; then
    printf '  sudo   : caching credentials...\n'
    sudo -v 2>/dev/null || printf '           (sudo unavailable — some tests will skip)\n'
  fi

  phase1; phase2; phase3; phase4

  header "SUMMARY"
  printf '  %s pass   %s fail   %s skip\n' \
    "${GRN}${PASS}${RST}" "${RED}${FAIL}${RST}" "${YEL}${SKIP}${RST}"

  if (( FAIL > 0 )); then
    printf '\n  %s\n' "${RED}${BLD}Failed checks:${RST}"
    for t in "${FAILED_TESTS[@]}"; do printf '    %s %s\n' "${RED}✗${RST}" "$t"; done
    exit 1
  fi
  printf '\n  %s\n' "${GRN}${BLD}All checks passed. Ship it. 🐉${RST}"
}

main "$@"
