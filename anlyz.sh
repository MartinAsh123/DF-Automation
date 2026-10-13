#!/usr/bin/env bash
# Author: Martin. Analyze a working copy of a disk or memory image.
set -uo pipefail
set +m  # Keep job control off so each setsid child keeps its recorded PID.
umask 077

usage() {
    cat <<'EOF'
Usage:
  bash anlyz.sh hdd <image-file> [--output <existing-or-new-directory>]
  bash anlyz.sh mem <image-file> --vol <trusted-volatility2-executable> \
      --profile <verified-profile> [--output <existing-or-new-directory>]
  bash anlyz.sh -h | --help

Each run creates a new directory under --output (default: ./df-results).
Memory mode reads volcom.txt without modifying it. --vol and --profile are
required: no bundled binary or automatically guessed profile is used.
Exit codes: 0 complete; 1 failed step/hash mismatch; 2 invalid input/setup;
130 interrupted; 143 terminated. Full outputs and command records are saved.
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 2; }
[[ ${1:-} == -h || ${1:-} == --help ]] && { usage; exit 0; }
[[ $# -ge 2 ]] || { usage >&2; exit 2; }
mode=$1
input=$2
shift 2
[[ $mode == mem || $mode == hdd ]] || die 'Mode must be mem or hdd.'
output_root=./df-results
vol=''
profile=''
while (($#)); do
    case $1 in
        --output|--vol|--profile)
            (($# >= 2)) && [[ -n $2 ]] || die "Missing value for $1."
            case $1 in
                --output) output_root=$2 ;;
                --vol) vol=$2 ;;
                --profile) profile=$2 ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

command -v python3 >/dev/null 2>&1 || die 'python3 is required.'
command -v timeout >/dev/null 2>&1 || die 'GNU timeout is required.'
command -v setsid >/dev/null 2>&1 || die 'util-linux setsid is required.'
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 2
helper=$script_dir/report.py
[[ -r $helper ]] || die "Missing reporting helper: $helper"
[[ -f $input && -r $input ]] || die 'Input must be a readable regular file.'
input=$(python3 "$helper" absolute "$input") || die 'Cannot resolve input path.'
plugins=()
if [[ $mode == mem ]]; then
    [[ -n $vol && -n $profile ]] || die 'Memory mode requires --vol and --profile.'
    [[ $profile =~ ^[A-Za-z0-9_]+$ ]] || die 'Invalid profile name.'
    [[ -f $vol && -x $vol ]] || die '--vol must name a trusted executable file (use its path).'
    vol=$(python3 "$helper" absolute "$vol") || die 'Cannot resolve --vol path.'
    [[ -r $script_dir/volcom.txt ]] || die 'Cannot read volcom.txt.'
    declare -A seen_plugins=()
    while IFS= read -r plugin || [[ -n $plugin ]]; do
        plugin=${plugin%$'\r'}
        [[ -z $plugin || $plugin == \#* ]] && continue
        [[ $plugin =~ ^[A-Za-z][A-Za-z0-9_]*$ && $plugin != imageinfo ]] || die "Invalid plugin name: $plugin"
        [[ ! ${seen_plugins[$plugin]+present} ]] || die "Duplicate plugin: $plugin"
        seen_plugins[$plugin]=1
        plugins+=("$plugin")
    done < "$script_dir/volcom.txt"
    ((${#plugins[@]})) || die 'volcom.txt contains no plugins.'
else
    [[ -z $vol && -z $profile ]] || die '--vol/--profile only apply to memory mode.'
    for dependency in binwalk bulk_extractor foremost strings; do
        command -v "$dependency" >/dev/null 2>&1 || die "Missing dependency: $dependency"
    done
fi

mkdir -p -- "$output_root" || die 'Cannot create output root.'
output_root=$(python3 "$helper" absolute "$output_root") || die 'Cannot resolve output root.'
run_dir=$(mktemp -d -- "$output_root/df-${mode}-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || die 'Cannot create run directory.'
mkdir -- "$run_dir/logs" "$run_dir/artifacts" || die 'Cannot create output subdirectories.'
python3 "$helper" init "$run_dir" "$input" "$mode" "$profile" "${plugins[@]}" || die 'Cannot hash input/create manifest.'
printf 'Results: %s\n' "$run_dir"
child_pid=''
interrupted=0
failed=0

interrupt() {
    interrupted=$1
    if [[ -n $child_pid ]]; then
        # Only signal the new session/process group created for this exact step.
        # The PID fallback covers interruption just before setsid establishes it.
        kill -TERM -- "-$child_pid" 2>/dev/null || kill -TERM -- "$child_pid" 2>/dev/null || true
        local attempt
        for ((attempt = 0; attempt < 20; attempt++)); do
            kill -0 -- "-$child_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "-$child_pid" 2>/dev/null || true
        kill -KILL -- "$child_pid" 2>/dev/null || true
    fi
}

finish() {
    local status=$?
    trap - EXIT INT TERM
    ((interrupted)) && status=$interrupted
    if ! python3 "$helper" finish "$run_dir" "$status"; then
        ((status == 0)) && status=1
    fi
    printf 'Summary: %s/summary.md\n' "$run_dir"
    exit "$status"
}
trap 'interrupt 130' INT
trap 'interrupt 143' TERM
trap finish EXIT

run_step() {
    local label=$1
    shift
    local started ended rc
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    setsid --wait "$@" > "$run_dir/logs/$label.stdout.txt" 2> "$run_dir/logs/$label.stderr.txt" &
    child_pid=$!
    wait "$child_pid"
    rc=$?
    if ((interrupted)); then
        wait "$child_pid" 2>/dev/null || true
        rc=$interrupted
    fi
    child_pid=''
    ended=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    python3 "$helper" step "$run_dir" "$label" "$started" "$ended" "$rc" "$@" || exit 1
    ((interrupted)) && exit "$interrupted"
    return "$rc"
}

version_probe() {
    local name=$1
    shift
    # A failed/unsupported version flag is retained, but does not fail analysis.
    run_step "version_$name" timeout --kill-after=2s 15s "$@" || true
    python3 "$helper" tool "$run_dir" "$name" "$1" || exit 1
}

if [[ $mode == hdd ]]; then
    version_probe binwalk "$(command -v binwalk)" --version
    version_probe bulk_extractor "$(command -v bulk_extractor)" -V
    version_probe foremost "$(command -v foremost)" -V
    version_probe strings "$(command -v strings)" --version
    run_step binwalk binwalk -eq "$input" --directory="$run_dir/artifacts/binwalk" || failed=1
    run_step bulk_extractor bulk_extractor "$input" -o "$run_dir/artifacts/bulk_extractor" || failed=1
    run_step foremost foremost -i "$input" -t all -o "$run_dir/artifacts/foremost" || failed=1
    run_step strings strings "$input" || failed=1
else
    version_probe volatility "$vol" --help
    run_step imageinfo "$vol" -f "$input" imageinfo || failed=1
    for plugin in "${plugins[@]}"; do
        run_step "$plugin" "$vol" -f "$input" "--profile=$profile" "$plugin" || failed=1
    done
fi
exit "$failed"
