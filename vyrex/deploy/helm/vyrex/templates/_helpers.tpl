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

{{/* Per-component selector labels: pass a dict {root, component}.
     Used for `spec.selector.matchLabels`, which Kubernetes treats as IMMUTABLE on an
     existing Deployment - so nothing may be added here without forcing a delete/recreate
     of every workload. Pod labels go in soc.podLabels below instead. */}}
{{- define "soc.selector" -}}
app.kubernetes.io/name: {{ include "soc.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Labels stamped on POD templates: the selector plus `part-of`.

     This exists because of a real defect. networkpolicy.yaml - the production air-gap
     primitive (DECISIONS D-042) - selects pods on `app.kubernetes.io/part-of: vyrex`, but
     `part-of` was only ever in soc.labels, which lands on the Deployment OBJECT. A
     NetworkPolicy selects PODS, and object labels are not pod labels, so the
     default-deny-egress policy matched ZERO of the 9 pod templates: every workload had
     unrestricted egress in Kubernetes while the chart claimed to be air-gapped.
     Verified by rendering the chart and counting - 9 pod templates, 0 with `part-of`.

     Kept separate from soc.selector so matchLabels stays byte-identical and existing
     deployments upgrade in place rather than needing to be recreated. */}}
{{- define "soc.podLabels" -}}
{{ include "soc.selector" . }}
app.kubernetes.io/part-of: vyrex
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
