# k3d live-apply + Velero DR drill — executed results

These two items previously could only be lint/render-validated because they need a real
Kubernetes cluster. They were executed for real on a k3d (K3s-in-Docker) cluster on the dev
host. Reproduce with the scripts in this directory; tooling: k3d v5.7.5 (k3s v1.30.6), helm
v3.16.4, velero v1.15.0.

## 1. Live-apply of the Helm chart

```
k3d cluster create soc-smoke --agents 1        # 2 nodes Ready (server + agent), k3s v1.30.6
helm lint   deploy/helm/vyrex            # 0 failed
helm template soc deploy/helm/vyrex      # 4 Deployment, 4 CronJob, 4 NetworkPolicy, 3 Service, 1 Ingress, 1 SA, 1 ConfigMap
helm install soc deploy/helm/vyrex -n vyrex --dry-run=server
                                               # STATUS: pending-install, REVISION: 1
                                               # => every manifest validated by the LIVE API server (schema + admission)
```

### Real workloads (actual built images as running pods)

`live-workloads.yaml` deploys the real `vyrex-api` + `vyrex-console` images
(imported via `k3d image import`) plus a Postgres:

```
kubectl get pods -n soc-live
  api-...       1/1 Running
  console-...   1/1 Running
  postgres-...  1/1 Running

curl http://api:8000/health   -> {"status":"ok","uptime_seconds":18.3}
curl http://api:8000/tenants  -> [{"id":"default","name":"Default organization", ...}]
curl http://console:8080/     -> HTTP 200
```

`/tenants` returning the seeded org proves the **api connected to Postgres and
`schema.ensure_schema()` created + seeded the new multi-tenancy tables** on a real cluster.

> Gotcha found & fixed: a Service named `postgres` makes Kubernetes inject a legacy
> `POSTGRES_PORT=tcp://…:5432` env var that clobbered the pydantic `postgres_port` setting
> (CrashLoopBackOff). Fixed with `enableServiceLinks: false` on the api pod.

## 2. Velero backup → destroy → restore drill

MinIO (`minio.yaml`) is the S3 backup store; Velero installed with the AWS plugin against it.

```
velero backup create soc-live-backup --include-namespaces soc-live --wait
  Phase: Completed   Total items to be backed up: 63        # written to MinIO bucket 'velero'

kubectl delete namespace soc-live                            # DESTROY
kubectl get ns soc-live -> Error: namespaces "soc-live" not found

velero restore create soc-live-restore --from-backup soc-live-backup --wait
  Restore completed with status: Completed

kubectl get pods -n soc-live  -> api 1/1, console 1/1, postgres 1/1 Running (all restored)
curl http://api:8000/tenants  -> [{"id":"default","name":"Default organization"}]   # working restore
```

The app namespace was fully destroyed and brought back from the Velero backup, and the
restored api re-established its DB connection — a real disaster-recovery cycle, not a dry run.

## Teardown

```
k3d cluster delete soc-smoke
```
