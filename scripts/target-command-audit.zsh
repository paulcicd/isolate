#!/usr/bin/env zsh
# Optional Isolate command audit hook for target hosts.
# Source from /etc/zsh/zshrc after setting:
#   ISOLATE_AUDIT_BASTION=auth@bastion.example.org

autoload -Uz add-zsh-hook
typeset -g __isolate_audit_last_command=""

__isolate_audit_preexec() {
  __isolate_audit_last_command="$1"
}

__isolate_audit_precmd() {
  local exit_code=$?
  local connection_id="${ISOLATE_CONNECTION_ID:-}"
  if [[ -z "$connection_id" || -z "$ISOLATE_AUDIT_BASTION" || -z "$__isolate_audit_last_command" ]]; then
    return "$exit_code"
  fi
  local command="$__isolate_audit_last_command"
  __isolate_audit_last_command=""
  ssh -o BatchMode=yes -o ClearAllForwardings=yes -o ConnectTimeout=3 \
      "$ISOLATE_AUDIT_BASTION" isolate command-log append \
    --connection-id "$connection_id" \
    --host-id "${ISOLATE_HOST_ID:-}" \
    --project "${ISOLATE_PROJECT:-}" \
    --cwd "$PWD" \
    --exit-code "$exit_code" \
    --shell zsh \
      --command "$command" >/dev/null 2>&1 &!
  return "$exit_code"
}

add-zsh-hook preexec __isolate_audit_preexec
add-zsh-hook precmd __isolate_audit_precmd
