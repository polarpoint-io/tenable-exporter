# Tenable Exporter — Architecture Document v1.0

> **Status:** Approved  
> **Author:** Winston (Architect Agent) via BMAD upstream session  
> **Date:** 2026-06-15  
> **Input:** [prd.md](prd.md)  
> **Downstream:** Sam (Platform Engineer) — generate manifests in `examples/gitops/`

---

## Overview

This document covers the Kubernetes deployment architecture for the tenable-exporter. It does not cover the exporter application itself (see the root README). It covers how the exporter is deployed, how it receives credentials, how it is updated, and how it is distributed to multiple clusters.

All implementation decisions made here must be traceable to a constraint or requirement in [prd.md](prd.md). If a decision is not traceable, it should not be in this document.

---

## Section 1: Chart strategy — consume upstream, don't fork

**Decision:** Use the upstream OCI Helm chart at `ghcr.io/polarpoint-io/charts/tenable-exporter` pinned to a specific version tag. Do not vendor or fork the chart.

**Rationale:** Polarpoint publishes and maintains the chart in this repo. Forking it into a separate location creates a maintenance burden with no benefit — we would be maintaining two copies of the same chart and would have to manually sync CVE fixes and new features. The chart already supports all the configuration surface we need (`existingSecret`, `scrapeInterval`, `filterProviders`).

**Version pinning:** Pin to the current stable release at deploy time (`1.1.3` as of 2026-06-15). Do not use `latest` — floating tags make deployments non-deterministic and complicate rollbacks.

**Update process:** When a new chart version ships, open a PR updating `targetRevision` in the ApplicationSet. The PR diff is the change record. ArgoCD will roll out the update after merge.

---

## Section 2: Multi-cluster deployment — ArgoCD ApplicationSet

**Decision:** Use an ArgoCD ApplicationSet with a list generator. One ApplicationSet manages all cluster deployments.

**Rationale:** We have three clusters today (`prod-aws-eu-west-1`, `prod-azure-uksouth`, `dev-aws-eu-west-1`). A single ArgoCD Application per cluster would require three separate manifests with duplicated configuration and no single place to see the deployment status. The ApplicationSet list generator gives us one manifest, one PR for cross-cutting changes, and a diff that shows exactly which clusters are affected by any change.

**Adding a new cluster:** Add one entry to the `spec.generators[0].list.elements` array. Open a PR. Merge. ArgoCD deploys. No other steps.

**Cluster addressing:** ApplicationSet entries reference clusters by their ArgoCD cluster name (matching the ArgoCD `cluster` secret label), not by raw API server URL. This decouples the manifest from cluster infrastructure details.

---

## Section 3: Scrape interval — differentiated by environment

**Decision:** 300 seconds in `prod` environments, 60 seconds in `dev` environments.

**Rationale (PRD constraint):** Tenable.io rate-limits export API requests. With approximately 2,000 assets across AWS and Azure, a 60-second scrape interval in prod would generate ~86,400 API calls per day per cluster. At prod scale this risks hitting Tenable's rate limit tier and causing 429 errors, which would produce gaps in the metrics.

**Rationale (dev):** Dev clusters have a smaller asset footprint (~200 assets) and faster feedback cycles are more important than API economy. 60 seconds is safe at dev scale.

**Implementation:** The scrape interval is passed as a Helm value (`tenable.scrapeInterval`) templated from the ApplicationSet generator element. It does not need to appear in a separate values file.

---

## Section 4: Secret management — ExternalSecrets Operator from Vault

**Decision:** Tenable API credentials flow: Vault → ExternalSecrets Operator → Kubernetes Secret (`tenable-credentials`). The Helm chart references this secret via `tenable.existingSecret: tenable-credentials`.

**Rationale (PRD constraint):** The PRD requires zero credentials in Git. This eliminates Sealed Secrets (encrypted credentials still live in Git, creates rotation complexity) and inline Helm values (credentials visible in ArgoCD UI and in the ApplicationSet YAML).

**Rationale (platform alignment):** ExternalSecrets Operator is already deployed on all three target clusters as the standard secret management path. Using it here is consistent with existing platform patterns, not a new dependency.

**Vault path:** `platform/tenable` — keys `access_key` and `secret_key`. The security team owns this Vault path. Rotation is their responsibility; ESO will refresh the Kubernetes Secret automatically on `refreshInterval: 1h`.

**ExternalSecret target:** `tenable-credentials` in the `monitoring` namespace. This name must match `tenable.existingSecret` in the Helm values exactly.

**Credential scope:** The Tenable.io API credentials must have the following permissions: `Can View` on all assets, `Can View` on all vulnerabilities, `Can View` on all scans. Read-only. Do not grant write or administrative permissions to the exporter service account.

---

## Section 5: Namespace

**Decision:** Deploy to the `monitoring` namespace on all clusters.

**Rationale:** The `monitoring` namespace already exists on all three target clusters and contains the kube-prometheus-stack (Prometheus, Alertmanager, Grafana). The tenable-exporter metrics will be scraped by the existing Prometheus instance via a `ServiceMonitor`. Deploying to a separate namespace would require additional RBAC to allow cross-namespace scraping and would break the existing ServiceMonitor discovery configuration.

**Namespace creation:** The `monitoring` namespace is managed by the kube-prometheus-stack ApplicationSet and must not be owned by the tenable-exporter ApplicationSet. The tenable-exporter ApplicationSet should set `syncPolicy.syncOptions: [CreateNamespace=false]` to prevent ArgoCD from creating or owning the namespace.

---

## Section 6: Resource sizing

**Decision:** Memory request `64Mi`, limit `128Mi`. CPU request `50m`, no limit.

**Rationale:** The exporter is a Python process that makes periodic Tenable API calls and holds the response in memory between scrapes. At 2,000 assets, the response payload is approximately 15-20MB JSON; after parsing and metric construction, resident memory stabilises around 50MB. The 64Mi request provides headroom. The 128Mi limit prevents runaway growth if the Tenable API returns unexpectedly large payloads.

**CPU:** The exporter is largely idle between scrapes. 50m request is sufficient. No CPU limit — brief spikes during metric parsing should not be throttled.

---

## Section 7: Provider filtering

**Decision:** Prod clusters filter to `aws,azure`. Dev cluster filters to `aws` only.

**Rationale:** We have no GCP estate. Filtering to `aws,azure` prevents the exporter from making API calls for GCP assets that don't exist and would return empty results. The dev cluster only needs to mirror the AWS side of prod for testing purposes.

**Implementation:** `tenable.filterProviders` is set per cluster in the ApplicationSet generator list, allowing it to be overridden per cluster without a separate values file.

---

## Decisions not made here

The following are explicitly out of scope for this architecture document:

- **Alerting rules** — Prometheus alerting rules for Tenable metrics are owned by the security team and will be delivered as a separate PrometheusRule manifest in the security team's GitOps directory
- **Grafana dashboards** — Owned by the security team
- **Tenable.io account configuration** — API credential creation and permission assignment are the security team's responsibility
- **Exporter application code** — See the root README and `exporter.py`
