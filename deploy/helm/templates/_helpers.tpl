{{/*
Expand the name of the chart.
*/}}
{{- define "pod-security-webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully-qualified app name from the chart name or nameOverride /
fullnameOverride.  Truncated to 63 characters to satisfy DNS label limits.
*/}}
{{- define "pod-security-webhook.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "pod-security-webhook.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "pod-security-webhook.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used in Deployment.spec.selector and Service.spec.selector.
These must remain stable across upgrades.
*/}}
{{- define "pod-security-webhook.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pod-security-webhook.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the TLS Secret that holds the webhook server certificate.
*/}}
{{- define "pod-security-webhook.tlsSecretName" -}}
{{- include "pod-security-webhook.fullname" . }}-tls
{{- end }}
