{{- define "isolate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 48 | trimSuffix "-" -}}
{{- end -}}
{{- define "isolate.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "isolate.name" .) | trunc 54 | trimSuffix "-" -}}
{{- end -}}
{{- define "isolate.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}
{{- define "isolate.account" -}}
{{- default (include "isolate.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}
{{- define "isolate.volumes" -}}
- name: runtime
  persistentVolumeClaim:
    claimName: {{ required "runtime.existingClaim is required" .Values.runtime.existingClaim | quote }}
- name: private-secrets
  {{- if .Values.init.enabled }}
  emptyDir:
    medium: Memory
  {{- else }}
  persistentVolumeClaim:
    claimName: {{ required "init.enabled=false requires a CSI/private secrets claim" .Values.runtime.privateSecretsClaim | quote }}
  {{- end }}
{{- if .Values.init.enabled }}
- name: bootstrap-secrets
  secret:
    secretName: {{ required "secrets.existingSecret is required" .Values.secrets.existingSecret | quote }}
    defaultMode: 256
{{- end }}
- name: temporary
  emptyDir:
    sizeLimit: 128Mi
{{- end -}}
{{- define "isolate.mounts" -}}
- name: runtime
  mountPath: {{ .Values.runtime.mountPath }}
- name: private-secrets
  mountPath: /run/isolate/secrets
  readOnly: true
- name: temporary
  mountPath: /tmp
{{- end -}}
{{- define "isolate.init" -}}
{{- if .Values.init.enabled }}
initContainers:
  - name: prepare-private-files
    image: {{ include "isolate.image" . | quote }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    command: ["python", "-I", "-B", "-c"]
    args:
      - |
        import os, pathlib, shutil
        private = pathlib.Path('/run/isolate/secrets')
        os.chmod(private, 0o700)
        os.chown(private, 2000, 2000)
        for source in pathlib.Path('/bootstrap').iterdir():
            if not source.name.startswith('.') and source.is_file():
                target = private / source.name
                shutil.copyfile(source, target)
                os.chmod(target, 0o600)
                os.chown(target, 2000, 2000)
        root = pathlib.Path(os.environ['ISOLATE_RUNTIME'])
        for name in ('', 'logs', 'cache', 'cache/recordings', 'jobs', 'spool', 'spool/evidence', 'spool/recordings'):
            path = root / name
            if path.is_symlink():
                raise RuntimeError('runtime paths cannot be symlinks')
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(path, 0o700)
            os.chown(path, 2000, 2000)
    env:
      - name: ISOLATE_RUNTIME
        value: {{ .Values.runtime.mountPath | quote }}
    securityContext:
      runAsUser: 0
      runAsGroup: 0
      runAsNonRoot: false
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
        add: [CHOWN, FOWNER, DAC_OVERRIDE]
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
      - name: bootstrap-secrets
        mountPath: /bootstrap
        readOnly: true
      - name: private-secrets
        mountPath: /run/isolate/secrets
      - name: runtime
        mountPath: {{ .Values.runtime.mountPath }}
{{- end }}
{{- end -}}
