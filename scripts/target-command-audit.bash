#!/usr/bin/env bash
# Optional Isolate command audit hook for target hosts.
# Source from /etc/profile.d/isolate-command-audit.sh after setting:
#   ISOLATE_AUDIT_BASTION=auth@bastion.example.org

__isolate_audit_last_command=""

__isolate_audit_preexec() {
    case "$BASH_COMMAND" in
        __isolate_audit_*|trap\ *) return ;;
    esac
    __isolate_audit_last_command="$BASH_COMMAND"
}

__isolate_audit_prompt() {
    local exit_code=$?
    local connection_id="${ISOLATE_CONNECTION_ID:-${connection_id:-}}"
    if [[ -z "$connection_id" || -z "$ISOLATE_AUDIT_BASTION" || -z "$__isolate_audit_last_command" ]]; then
        return "$exit_code"
    fi
    local command="$__isolate_audit_last_command"
    __isolate_audit_last_command=""
    trap - DEBUG
    ssh -o BatchMode=yes -o ClearAllForwardings=yes -o ConnectTimeout=3 \
        "$ISOLATE_AUDIT_BASTION" isolate command-log append \
        --connection-id "$connection_id" \
        --host-id "${ISOLATE_HOST_ID:-}" \
        --project "${ISOLATE_PROJECT:-}" \
        --cwd "$PWD" \
        --exit-code "$exit_code" \
        --shell bash \
        --command "$command" >/dev/null 2>&1 &
    trap '__isolate_audit_preexec' DEBUG
    return "$exit_code"
}

if declare -p PROMPT_COMMAND 2>/dev/null | grep -q '^declare -a'; then
    PROMPT_COMMAND=(__isolate_audit_prompt "${PROMPT_COMMAND[@]}")
else
    PROMPT_COMMAND="__isolate_audit_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
trap '__isolate_audit_preexec' DEBUG
