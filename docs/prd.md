# Tenable Exporter — Kubernetes Deployment PRD v1.0

> **Status:** Approved  
> **Author:** Preston (PM Agent) via BMAD upstream session  
> **Date:** 2026-06-15  
> **Downstream:** See [architecture.md](architecture.md)

---

## Problem

The security team has Tenable.io providing continuous vulnerability scanning across the Polarpoint AWS and Azure estate, but there's no way to alert on critical CVEs or track remediation velocity in our existing Grafana/Prometheus stack.

Currently, security findings are only visible by logging into the Tenable UI. There's no integration with our on-call tooling. Platform engineers are fielding ad-hoc requests to query Tenable directly, and when a critical CVE lands the first question is always "does this affect us?" — a question nobody can answer without checking Tenable manually.

The tenable-exporter already exists as a Prometheus exporter for Tenable.io (Python, published on PyPI and GHCR with a Helm chart). This PRD covers deploying it properly across our Kubernetes clusters, not building a new tool.

---

## Users

**Primary — Security platform team**  
Need Grafana dashboards showing vulnerability counts by severity, subscription, and region. Need to set Prometheus alerts on critical/high CVE counts that page the security on-call, not the platform on-call.

**Secondary — SRE teams**  
Want per-subscription vulnerability counts visible in their existing service dashboards. Don't want to log into Tenable; they want a metric they can already see in their runbooks.

---

## Success metrics

- Tenable metrics available in Prometheus within 10 minutes of initial deploy
- P95 metric freshness < 2× scrape interval (data should not go stale silently)
- Critical vuln count alerts firing within one scrape interval of a new Tenable finding
- **Zero Tenable API credentials stored in Git or in any Helm values file**
- Deployment to a new cluster via a single PR to the GitOps repo (no manual steps)

---

## Requirements

### Must have (v1)

- Deploy to three clusters: `prod-aws-eu-west-1`, `prod-azure-uksouth`, `dev-aws-eu-west-1`
- Filter metrics to AWS and Azure providers (GCP not in scope — we have no GCP estate)
- Tenable API credentials managed via the platform secret management system (not stored in Git)
- Scrape interval differentiated by environment to avoid Tenable API rate limits in prod
- All deployments in the `monitoring` namespace alongside the existing Prometheus stack
- GitOps-native: all changes via PR, no manual `kubectl apply` or `helm install`

### Nice to have (v1)

- Example ArgoCD ApplicationSet and ExternalSecret in the repo for adopters outside Polarpoint
- Prometheus recording rules for the most common security team queries (vuln counts by severity)

### Out of scope (v1)

- Tenable.sc (on-prem scanner) — Tenable.io only
- Per-developer vulnerability views — the security team owns the data model
- Automatic remediation triggering from Prometheus alerts
- GCP provider filtering — no GCP estate at time of writing

---

## Constraints

1. **GitOps-native** — no `helm install` by hand, no direct `kubectl apply`. All state in Git.
2. **Credentials must not touch Git** — Tenable API keys are sensitive. The architecture must route them through the platform's existing secret management path, not through Helm values.
3. **Tenable API rate limits** — Tenable.io rate-limits export requests. Prod scrape interval must not cause 429s given our asset count (~2,000 assets across AWS + Azure). Dev can be more aggressive for faster feedback.
4. **Consume upstream chart** — Do not fork or vendor the tenable-exporter Helm chart. Polarpoint publishes it; pin to a specific version tag.
5. **Monitoring namespace** — Must coexist with existing kube-prometheus-stack deployment. Do not create a new namespace.

---

## Open questions (resolved)

| Question | Decision |
|---|---|
| Sealed Secrets vs ExternalSecrets for credential management? | ExternalSecrets pulling from Vault — already in use on all three clusters |
| Single ArgoCD Application per cluster or ApplicationSet? | ApplicationSet with list generator — one-line PR to add a cluster |
| What scrape interval avoids Tenable rate limits in prod? | 300s (5 min) in prod, 60s in dev — confirmed with security team |
| Which Helm chart version to pin? | Latest stable at time of deploy: `1.1.3` — update via PR when new versions ship |

---

## Acceptance criteria

- [ ] `tenable_vulnerabilities_total` metric visible in Prometheus UI on all three clusters
- [ ] `tenable_vulnerabilities_by_subscription_total` broken down by `provider` label
- [ ] No secrets in `gitops/` or `charts/` directories (verified by Gitleaks scan in CI)
- [ ] Adding a fourth cluster requires only a PR adding one entry to the ApplicationSet generator list
- [ ] Quinn has reviewed all generated manifests against this PRD and architecture.md
