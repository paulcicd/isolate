#!/usr/bin/env zsh
# Optional Isolate command audit hook for target hosts.
# Source from /etc/zsh/zshrc after setting:
#   ISOLATE_AUDIT_BASTION=auth@bastion.example.org

typeset -g __isolate_audit_last_command=""

preexec() {
  __isolate_audit_last_command="$1"
}

precmd() {
  local exit_code=$?
  local connection_id="${ISOLATE_CONNECTION_ID:-}"
  if [[ -z "$connection_id" || -z "$ISOLATE_AUDIT_BASTION" || -z "$__isolate_audit_last_command" ]]; then
    return "$exit_code"
  fi
  ssh -o BatchMode=yes "$ISOLATE_AUDIT_BASTION" isolate command-log append \
    --connection-id "$connection_id" \
    --host-id "${ISOLATE_HOST_ID:-}" \
    --project "${ISOLATE_PROJECT:-}" \
    --cwd "$PWD" \
    --exit-code "$exit_code" \
    --shell zsh \
    --command "$__isolate_audit_last_command" >/dev/null 2>&1 || true
  __isolate_audit_last_command=""
  return "$exit_code"
}
