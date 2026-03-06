{{/*
Expand the name of the chart.
*/}}
{{- define "ritapi-advanced.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ritapi-advanced.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "ritapi-advanced.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ritapi-advanced.labels" -}}
helm.sh/chart: {{ include "ritapi-advanced.chart" . }}
{{ include "ritapi-advanced.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ritapi-advanced.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ritapi-advanced.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "ritapi-advanced.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ritapi-advanced.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Redis URL — prefers external, falls back to bundled service
*/}}
{{- define "ritapi-advanced.redisUrl" -}}
{{- if .Values.redis.externalUrl }}
{{- .Values.redis.externalUrl }}
{{- else }}
{{- printf "redis://:%s@%s-redis:6379/1" .Values.secrets.redisPassword (include "ritapi-advanced.fullname" .) }}
{{- end }}
{{- end }}
