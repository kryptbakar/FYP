{{/* Common naming + labels */}}
{{- define "soc.name" -}}vyrex{{- end -}}

{{- define "soc.fullname" -}}
{{- printf "%s-%s" .Release.Name "vyrex" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "soc.labels" -}}
app.kubernetes.io/name: {{ include "soc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: vyrex
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* Per-component selector labels: pass a dict {root, component} */}}
{{- define "soc.selector" -}}
app.kubernetes.io/name: {{ include "soc.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Fully-qualified image ref from registry + name + tag */}}
{{- define "soc.image" -}}
{{- $root := .root -}}
{{- printf "%s/%s:%s" $root.Values.global.imageRegistry .name (default $root.Values.global.imageTag .tag) -}}
{{- end -}}

{{/* Shared pod securityContext */}}
{{- define "soc.podSecurity" -}}
runAsNonRoot: {{ .Values.podSecurity.runAsNonRoot }}
runAsUser: {{ .Values.podSecurity.runAsUser }}
fsGroup: {{ .Values.podSecurity.runAsUser }}
seccompProfile:
  type: {{ .Values.podSecurity.seccompProfile }}
{{- end -}}

{{- define "soc.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: {{ .Values.podSecurity.readOnlyRootFilesystem }}
capabilities:
  drop: ["ALL"]
{{- end -}}
