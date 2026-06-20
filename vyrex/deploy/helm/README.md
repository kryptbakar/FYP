# helm/

`vyrex/` — the Helm chart for the SOC Central product workloads (api, console,
workers, ingest-edge, the cron jobs) and the security primitives (default-deny egress
NetworkPolicies, OIDC-protected ingress). See **[../README.md](../README.md)** for the
full air-gapped K3s deployment guide (operators, Vault, identity, backup, GitOps).

```bash
helm lint   deploy/helm/vyrex
helm install soc deploy/helm/vyrex -n vyrex --create-namespace
```
