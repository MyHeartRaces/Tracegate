{{- define "tracegate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tracegate.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "tracegate.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tracegate.namespace" -}}
{{- .Values.namespace.name | default .Release.Namespace -}}
{{- end -}}

{{- define "tracegate.labels" -}}
app.kubernetes.io/name: {{ include "tracegate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: tracegate
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
tracegate.io/architecture: {{ .Values.global.architectureRevision | quote }}
{{- end -}}

{{- define "tracegate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tracegate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tracegate.image" -}}
{{- $repo := required "image.repository is required" .repository -}}
{{- $tag := .tag | default "latest" -}}
{{- $digest := .digest | default "" -}}
{{- if $digest -}}
{{- printf "%s@%s" $repo $digest -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}

{{- define "tracegate.controlPlaneSecretName" -}}
{{- if .Values.controlPlane.auth.existingSecretName -}}
{{- .Values.controlPlane.auth.existingSecretName -}}
{{- else -}}
{{- printf "%s-control-plane-auth" (include "tracegate.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "tracegate.postgresSecretName" -}}
{{- printf "%s-postgres-auth" (include "tracegate.fullname" .) -}}
{{- end -}}

{{- define "tracegate.privateProfilesSecretName" -}}
{{- .Values.privateProfiles.existingSecretName | default (printf "%s-private-profiles" (include "tracegate.fullname" .)) -}}
{{- end -}}

{{- define "tracegate.isExampleHost" -}}
{{- $host := lower (trimSuffix "." (trim (toString .))) -}}
{{- if or (eq $host "example.com") (hasSuffix ".example.com" $host) -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{- define "tracegate.entryHost" -}}
{{- $configured := trim (toString .Values.controlPlane.env.defaultEntryHost) -}}
{{- $roleHost := trim (toString .Values.gateway.roles.entry.tls.serverName) -}}
{{- if and $roleHost (or (not $configured) (eq (include "tracegate.isExampleHost" $configured) "true")) -}}
{{- $roleHost -}}
{{- else -}}
{{- $configured -}}
{{- end -}}
{{- end -}}

{{- define "tracegate.transitHost" -}}
{{- $configured := trim (toString .Values.controlPlane.env.defaultTransitHost) -}}
{{- $roleHost := trim (toString .Values.gateway.roles.transit.tls.serverName) -}}
{{- if and $roleHost (or (not $configured) (eq (include "tracegate.isExampleHost" $configured) "true")) -}}
{{- $roleHost -}}
{{- else -}}
{{- $configured -}}
{{- end -}}
{{- end -}}

{{- define "tracegate.roleTlsServerName" -}}
{{- $root := .root -}}
{{- $roleName := .role -}}
{{- $role := index $root.Values.gateway.roles $roleName -}}
{{- $configured := trim (toString $role.tls.serverName) -}}
{{- $defaultHost := ternary (include "tracegate.entryHost" $root) (include "tracegate.transitHost" $root) (eq $roleName "entry") -}}
{{- if and $defaultHost (eq (include "tracegate.isExampleHost" $configured) "true") (ne (include "tracegate.isExampleHost" $defaultHost) "true") -}}
{{- $defaultHost -}}
{{- else -}}
{{- $configured -}}
{{- end -}}
{{- end -}}

{{- define "tracegate.roleName" -}}
{{- printf "%s-gateway-%s" (include "tracegate.fullname" .root) .role -}}
{{- end -}}

{{- define "tracegate.transitRouterName" -}}
{{- .Values.transitRouter.name | default (printf "%s-transit-router" (include "tracegate.fullname" .)) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
