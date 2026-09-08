{{- define "okoscope.fullname" -}}{{ default .Release.Name .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "okoscope.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: okoscope
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "okoscope.image" -}}{{ index . "repository" }}{{ if index . "digest" }}@{{ index . "digest" }}{{ else }}:{{ index . "tag" }}{{ end }}{{- end }}
{{- define "okoscope.internalSecret" -}}{{ default (printf "%s-internal" (include "okoscope.fullname" .)) .Values.internalSecret.existingSecret }}{{- end }}
{{- define "okoscope.corsOrigins" -}}
{{- $origins := .Values.server.corsOrigins -}}
{{- if .Values.ingress.web.enabled -}}
{{- $scheme := ternary "https" "http" (ne .Values.ingress.web.tlsSecret "") -}}
{{- $origins = prepend $origins (printf "%s://%s" $scheme .Values.ingress.web.host) -}}
{{- end -}}
{{- join "," (uniq $origins) -}}
{{- end }}
