{{- define "okoscope-agent.name" -}}{{ default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "okoscope-agent.fullname" -}}{{ default (printf "%s-%s" .Release.Name (include "okoscope-agent.name" .)) .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "okoscope-agent.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "okoscope-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "okoscope-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "okoscope-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "okoscope-agent.image" -}}{{ .Values.image.repository }}{{ if .Values.image.digest }}@{{ .Values.image.digest }}{{ else }}:{{ required "image.tag is required when image.digest is empty" .Values.image.tag }}{{ end }}{{- end }}
