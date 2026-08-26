#!/usr/bin/env bash
# Optional Isolate command audit hook for target hosts.
# Source from /etc/profile.d/isolate-command-audit.sh after setting:
#   ISOLATE_AUDIT_BASTION=auth@bastion.example.org

__isolate_audit_last_command=""

__isolate_audit_preexec() {
    __isolate_audit_last_command="$BASH_COMMAND"
}

__isolate_audit_prompt() {
    local exit_code=$?
    local connection_id="${ISOLATE_CONNECTION_ID:-${connection_id:-}}"
    if [[ -z "$connection_id" || -z "$ISOLATE_AUDIT_BASTION" || -z "$__isolate_audit_last_command" ]]; then
        return "$exit_code"
    fi
    ssh -o BatchMode=yes "$ISOLATE_AUDIT_BASTION" isolate command-log append \
        --connection-id "$connection_id" \
        --host-id "${ISOLATE_HOST_ID:-}" \
        --project "${ISOLATE_PROJECT:-}" \
        --cwd "$PWD" \
        --exit-code "$exit_code" \
        --shell bash \
        --command "$__isolate_audit_last_command" >/dev/null 2>&1 || true
    __isolate_audit_last_command=""
    return "$exit_code"
}

trap '__isolate_audit_preexec' DEBUG
PROMPT_COMMAND="__isolate_audit_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
