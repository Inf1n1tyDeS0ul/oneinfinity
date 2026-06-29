#!/usr/bin/env bash
# run_go_tests.sh — Build each Go module under src/go/ and report pass/fail.
# Usage: bash tests/go/run_go_tests.sh [--verbose]
#
# Exit code: 0 if every module builds; non-zero if any fail.
# Compatible with bash 3+ (macOS default) — no mapfile/readarray required.

VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GO_SRC="${PROJECT_ROOT}/src/go"

PASS=0
FAIL=0
SKIP=0
FAILED_MODULES=""

# Colour codes (degrade gracefully when not a tty)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; RESET='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; RESET=''
fi

hr() { printf '%.0s─' {1..60}; echo; }

hr
echo "  One&Infinity — Go sidecar build check"
echo "  Root: ${GO_SRC}"
hr

# ── Discover all Go modules ──────────────────────────────────────────────────
# A "module" is any subdirectory that contains a go.mod file.
# Use a while-read loop (bash 3 compatible; no mapfile needed).
MOD_LIST=""
while IFS= read -r go_mod; do
    dir="$(dirname "${go_mod}")"
    MOD_LIST="${MOD_LIST}${dir}"$'\n'
done < <(find "${GO_SRC}" -maxdepth 2 -name "go.mod" | sort)

if [[ -z "${MOD_LIST}" ]]; then
    echo "${YELLOW}WARN${RESET}  No go.mod files found under ${GO_SRC}"
    exit 0
fi

# ── Build each module ────────────────────────────────────────────────────────
while IFS= read -r mod_dir; do
    [[ -z "${mod_dir}" ]] && continue
    module_name="$(basename "${mod_dir}")"
    printf "  %-28s " "${module_name}"

    if [[ ! -f "${mod_dir}/go.mod" ]]; then
        printf "${YELLOW}SKIP${RESET}  (no go.mod)\n"
        SKIP=$(( SKIP + 1 ))
        continue
    fi

    if [[ ${VERBOSE} -eq 1 ]]; then
        build_output=$(cd "${mod_dir}" && go build ./... 2>&1) && build_rc=0 || build_rc=$?
        [[ -n "${build_output}" ]] && echo && echo "${build_output}"
    else
        build_output=$(cd "${mod_dir}" && go build ./... 2>&1) && build_rc=0 || build_rc=$?
    fi

    if [[ ${build_rc} -eq 0 ]]; then
        printf "${GREEN}PASS${RESET}\n"
        PASS=$(( PASS + 1 ))
    else
        printf "${RED}FAIL${RESET}\n"
        FAIL=$(( FAIL + 1 ))
        FAILED_MODULES="${FAILED_MODULES}${module_name}"$'\n'
        if [[ -n "${build_output}" ]]; then
            echo "${build_output}" | sed 's/^/    /'
        fi
    fi
done <<< "${MOD_LIST}"

# ── Optional: go vet ─────────────────────────────────────────────────────────
if [[ ${VERBOSE} -eq 1 && ${PASS} -gt 0 ]]; then
    hr
    echo "  go vet pass"
    while IFS= read -r mod_dir; do
        [[ -z "${mod_dir}" ]] && continue
        module_name="$(basename "${mod_dir}")"
        printf "  %-28s " "${module_name} (vet)"
        vet_out=$(cd "${mod_dir}" && go vet ./... 2>&1) && vet_rc=0 || vet_rc=$?
        if [[ ${vet_rc} -eq 0 ]]; then
            printf "${GREEN}PASS${RESET}\n"
        else
            printf "${YELLOW}WARN${RESET}\n"
            [[ -n "${vet_out}" ]] && echo "${vet_out}" | sed 's/^/    /'
        fi
    done <<< "${MOD_LIST}"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
hr
TOTAL=$(( PASS + FAIL + SKIP ))
printf "  Results: ${GREEN}%d PASS${RESET}  ${RED}%d FAIL${RESET}  ${YELLOW}%d SKIP${RESET}  (total %d)\n" \
    "${PASS}" "${FAIL}" "${SKIP}" "${TOTAL}"

if [[ -n "${FAILED_MODULES}" ]]; then
    echo
    echo "  Failed modules:"
    while IFS= read -r m; do
        [[ -z "${m}" ]] && continue
        echo "    ${RED}x${RESET} ${m}"
    done <<< "${FAILED_MODULES}"
fi
hr

[[ ${FAIL} -eq 0 ]]
