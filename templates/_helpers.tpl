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
Determine which k8saudit plugin to use
*/}}
{{- define "sib-k8s.auditPlugin.name" -}}
{{- if eq .Values.auditPlugin.type "k8saudit" }}
{{- print "k8saudit" }}
{{- else if eq .Values.auditPlugin.type "k8saudit-eks" }}
{{- print "k8saudit-eks" }}
{{- else if eq .Values.auditPlugin.type "k8saudit-gke" }}
{{- print "k8saudit-gke" }}
{{- else if eq .Values.auditPlugin.type "k8saudit-aks" }}
{{- print "k8saudit-aks" }}
{{- else }}
{{- print "k8saudit" }}
{{- end }}
{{- end }}

{{/*
Determine the plugin library path
*/}}
{{- define "sib-k8s.auditPlugin.library" -}}
{{- if eq .Values.auditPlugin.type "k8saudit" }}
{{- print "libk8saudit.so" }}
{{- else if eq .Values.auditPlugin.type "k8saudit-eks" }}
{{- print "libk8saudit-eks.so" }}
{{- else if eq .Values.auditPlugin.type "k8saudit-gke" }}
{{- print "libk8saudit-gke.so" }}
{{- else if eq .Values.auditPlugin.type "k8saudit-aks" }}
{{- print "libk8saudit-aks.so" }}
{{- else }}
{{- print "libk8saudit.so" }}
{{- end }}
{{- end }}

{{/*
Generate Falco plugin open_params based on plugin type
*/}}
{{- define "sib-k8s.auditPlugin.openParams" -}}
{{- if eq .Values.auditPlugin.type "k8saudit" }}
{{- printf "http://:%d/k8s-audit" (int .Values.auditPlugin.k8saudit.port) }}
{{- else if eq .Values.auditPlugin.type "k8saudit-eks" }}
{{- with .Values.auditPlugin.k8sauditEks }}
{{- printf "%s:%s:%s" .region .logGroup .logStream }}
{{- end }}
{{- else if eq .Values.auditPlugin.type "k8saudit-gke" }}
{{- with .Values.auditPlugin.k8sauditGke }}
{{- printf "%s:%s:%s" .projectId .location .clusterId }}
{{- end }}
{{- else if eq .Values.auditPlugin.type "k8saudit-aks" }}
{{- with .Values.auditPlugin.k8sauditAks }}
{{- printf "%s/%s/%s" .subscriptionId .resourceGroup .clusterName }}
{{- end }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end }}

{{/*
Generate Falco plugin init_config based on plugin type
*/}}
{{- define "sib-k8s.auditPlugin.initConfig" -}}
{{- if eq .Values.auditPlugin.type "k8saudit" }}
{{- with .Values.auditPlugin.k8saudit }}
{{- $config := dict }}
{{- if .maxEventBytes }}
{{- $_ := set $config "maxEventBytes" .maxEventBytes }}
{{- end }}
{{- if .sslCertificate }}
{{- $_ := set $config "sslCertificate" .sslCertificate }}
{{- end }}
{{- if $config }}
{{- toJson $config }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end }}
{{- else if eq .Values.auditPlugin.type "k8saudit-eks" }}
{{- with .Values.auditPlugin.k8sauditEks }}
{{- $config := dict "shift" .shift "pollingInterval" .pollingInterval }}
{{- if .maxEventSize }}
{{- $_ := set $config "maxEventSize" .maxEventSize }}
{{- end }}
{{- if .profile }}
{{- $_ := set $config "profile" .profile }}
{{- end }}
{{- toJson $config }}
{{- end }}
{{- else if eq .Values.auditPlugin.type "k8saudit-gke" }}
{{- with .Values.auditPlugin.k8sauditGke }}
{{- $config := dict "pollingInterval" .pollingInterval }}
{{- if .credentialsFile }}
{{- $_ := set $config "credentialsFile" .credentialsFile }}
{{- end }}
{{- toJson $config }}
{{- end }}
{{- else if eq .Values.auditPlugin.type "k8saudit-aks" }}
{{- with .Values.auditPlugin.k8sauditAks }}
{{- $config := dict "eventHubNamespace" .eventHubNamespace "eventHubName" .eventHubName "consumerGroup" .consumerGroup }}
{{- if .connectionString }}
{{- $_ := set $config "connectionString" .connectionString }}
{{- end }}
{{- toJson $config }}
{{- end }}
{{- else }}
{{- print "" }}
{{- end }}
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
Generate falcoctl artifact refs based on plugin type
*/}}
{{- define "sib-k8s.falcoctl.installRefs" -}}
{{- $pluginName := include "sib-k8s.auditPlugin.name" . }}
{{- $pluginVersion := .Values.auditPlugin.version }}
{{- $rulesVersion := .Values.auditPlugin.rulesVersion }}
{{- $refs := list }}
{{- $refs = append $refs (printf "%s-rules:%s" $pluginName $rulesVersion) }}
{{- $refs = append $refs (printf "%s:%s" $pluginName $pluginVersion) }}
{{- if .Values.syscallMonitoring.enabled }}
{{- $refs = append $refs "falco-rules:5" }}
{{- end }}
{{- toJson $refs }}
{{- end }}

{{/*
Generate falcoctl follow refs based on plugin type
*/}}
{{- define "sib-k8s.falcoctl.followRefs" -}}
{{- $pluginName := include "sib-k8s.auditPlugin.name" . }}
{{- $rulesVersion := .Values.auditPlugin.rulesVersion }}
{{- $refs := list }}
{{- $refs = append $refs (printf "%s-rules:%s" $pluginName $rulesVersion) }}
{{- if .Values.syscallMonitoring.enabled }}
{{- $refs = append $refs "falco-rules:5" }}
{{- end }}
{{- toJson $refs }}
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
