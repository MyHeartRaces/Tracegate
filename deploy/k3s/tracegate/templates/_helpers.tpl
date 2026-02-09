{{- define "tracegate.namespace" -}}
{{- .Values.namespace.name -}}
{{- end -}}

{{- define "tracegate.fullname" -}}
{{- .Release.Name -}}
{{- end -}}

{{- define "tracegate.labels" -}}
app.kubernetes.io/name: tracegate
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tracegate.image" -}}
{{ .repository }}:{{ .tag }}
{{- end -}}

{{- define "tracegate.databaseUrl" -}}
{{- if .Values.controlPlane.externalDatabaseUrl -}}
{{ .Values.controlPlane.externalDatabaseUrl }}
{{- else -}}
postgresql+asyncpg://{{ .Values.controlPlane.postgres.username }}:{{ .Values.controlPlane.postgres.password }}@{{ include "tracegate.fullname" . }}-postgres:5432/{{ .Values.controlPlane.postgres.database }}
{{- end -}}
{{- end -}}
