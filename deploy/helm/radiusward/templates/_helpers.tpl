{{/*
Copyright 2026 The radiusward Authors
SPDX-License-Identifier: Apache-2.0
*/}}

{{- define "radiusward.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "radiusward.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* selector labels of a component: node or server */}}
{{- define "radiusward.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "radiusward.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/* members by StatefulSet DNS name (ADR 0062) */}}
{{- define "radiusward.members" -}}
{{- $fn := include "radiusward.fullname" . -}}
{{- $names := list -}}
{{- range $i := until (int .Values.node.replicas) -}}
{{- $names = append $names (printf "%s-node-%d.%s-node.%s.svc.%s" $fn $i $fn $.Release.Namespace $.Values.clusterDomain) -}}
{{- end -}}
{{- join "," $names -}}
{{- end -}}

{{/* sizes per profile: heap + direct (deploy/docker/entrypoint.sh) + shm + ~15 % */}}
{{- define "radiusward.preset" -}}
{{- $p := dict
  "small"    (dict "nodeMemory" "1536Mi" "nodeCpu" "1" "nodeShm" "512Mi" "serverMemory" "768Mi"  "serverCpu" "1" "serverShm" "128Mi")
  "standard" (dict "nodeMemory" "4Gi"    "nodeCpu" "2" "nodeShm" "1Gi"   "serverMemory" "1280Mi" "serverCpu" "2" "serverShm" "256Mi")
  "large"    (dict "nodeMemory" "11Gi"   "nodeCpu" "4" "nodeShm" "2Gi"   "serverMemory" "2304Mi" "serverCpu" "4" "serverShm" "256Mi") -}}
{{- toYaml (get $p .Values.profile) -}}
{{- end -}}

{{- define "radiusward.nodeResources" -}}
{{- if .Values.node.resources -}}
{{ toYaml .Values.node.resources }}
{{- else -}}
{{- $p := include "radiusward.preset" . | fromYaml -}}
requests: {cpu: {{ $p.nodeCpu | quote }}, memory: {{ $p.nodeMemory }}}
limits: {cpu: {{ $p.nodeCpu | quote }}, memory: {{ $p.nodeMemory }}}
{{- end -}}
{{- end -}}

{{- define "radiusward.serverResources" -}}
{{- if .Values.server.resources -}}
{{ toYaml .Values.server.resources }}
{{- else -}}
{{- $p := include "radiusward.preset" . | fromYaml -}}
requests: {cpu: {{ $p.serverCpu | quote }}, memory: {{ $p.serverMemory }}}
limits: {cpu: {{ $p.serverCpu | quote }}, memory: {{ $p.serverMemory }}}
{{- end -}}
{{- end -}}

{{- define "radiusward.nodeShm" -}}
{{- .Values.node.shmSize | default (include "radiusward.preset" . | fromYaml).nodeShm -}}
{{- end -}}

{{- define "radiusward.serverShm" -}}
{{- .Values.server.shmSize | default (include "radiusward.preset" . | fromYaml).serverShm -}}
{{- end -}}

{{/* pod-level security context */}}
{{- define "radiusward.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ .Values.securityContext.runAsUser }}
runAsGroup: {{ .Values.securityContext.runAsGroup }}
fsGroup: {{ .Values.securityContext.fsGroup }}
seccompProfile: {type: RuntimeDefault}
{{- end -}}

{{- define "radiusward.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
{{- end -}}

{{/* anti-affinity of a component: hard | soft | none */}}
{{- define "radiusward.affinity" -}}
{{- $sel := include "radiusward.selector" (dict "root" .root "component" .component) | fromYaml -}}
{{- if eq .mode "hard" }}
podAntiAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector: {matchLabels: {{ toJson $sel }}}
      topologyKey: kubernetes.io/hostname
{{- else if eq .mode "soft" }}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector: {matchLabels: {{ toJson $sel }}}
        topologyKey: kubernetes.io/hostname
{{- end }}
{{- end -}}

{{- define "radiusward.scrapeAnnotations" -}}
{{- if .Values.metrics.podAnnotations }}
prometheus.io/scrape: "true"
prometheus.io/port: "9090"
prometheus.io/path: /metrics
{{- end }}
{{- end -}}

{{/* the Secret the chart creates for passwords given in values */}}
{{- define "radiusward.secretName" -}}
{{ include "radiusward.fullname" . }}-secrets
{{- end -}}

{{/* RADIUS ports of a server Service */}}
{{- define "radiusward.serverPorts" -}}
- {name: auth, port: {{ .ports.auth }}, targetPort: auth, protocol: UDP}
- {name: acct, port: {{ .ports.acct }}, targetPort: acct, protocol: UDP}
{{- if .coa.enabled }}
- {name: coa, port: {{ .coa.port }}, targetPort: coa, protocol: UDP}
{{- end }}
{{- if .radsec.enabled }}
- {name: radsec, port: {{ .radsec.port }}, targetPort: radsec, protocol: TCP}
{{- end }}
{{- end -}}
