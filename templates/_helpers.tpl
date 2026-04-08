{{/*
Expand the name of the chart.
*/}}
{{- define "sib-k8s.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "sib-k8s.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "sib-k8s.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sib-k8s.labels" -}}
helm.sh/chart: {{ include "sib-k8s.chart" . }}
{{ include "sib-k8s.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sib-k8s.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sib-k8s.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Analysis service name
*/}}
{{- define "sib-k8s.analysis.fullname" -}}
{{- printf "%s-analysis" (include "sib-k8s.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Analysis service labels
*/}}
{{- define "sib-k8s.analysis.labels" -}}
{{ include "sib-k8s.labels" . }}
app.kubernetes.io/component: analysis
{{- end }}

{{/*
Analysis service selector labels
*/}}
{{- define "sib-k8s.analysis.selectorLabels" -}}
{{ include "sib-k8s.selectorLabels" . }}
app.kubernetes.io/component: analysis
{{- end }}

{{/*
Determine Falco controller kind based on configuration
*/}}
{{- define "sib-k8s.falco.controllerKind" -}}
{{- if .Values.falco.controller.kind }}
{{- .Values.falco.controller.kind }}
{{- else if .Values.syscallMonitoring.enabled }}
{{- print "daemonset" }}
{{- else }}
{{- print "deployment" }}
{{- end }}
{{- end }}

{{/*
Generate Falcosidekick Loki URL
*/}}
{{- define "sib-k8s.loki.url" -}}
{{- if .Values.loki.enabled }}
{{- printf "http://%s-loki:3100" .Release.Name }}
{{- else if .Values.falcosidekick.config.loki.hostport }}
{{- .Values.falcosidekick.config.loki.hostport }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end }}

{{/*
Generate Analysis service URL
*/}}
{{- define "sib-k8s.analysis.url" -}}
{{- printf "http://%s:%d" (include "sib-k8s.analysis.fullname" .) (int .Values.analysis.service.port) }}
{{- end }}

{{/*
Generate Falcosidekick URL for Falco HTTP output
*/}}
{{- define "sib-k8s.falcosidekick.url" -}}
{{- if .Values.falcosidekick.enabled }}
{{- printf "http://%s-falcosidekick:2801" .Release.Name }}
{{- else if .Values.falco.falco.http_output.url }}
{{- .Values.falco.falco.http_output.url }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end }}

{{/*
Image pull secrets helper
*/}}
{{- define "sib-k8s.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
