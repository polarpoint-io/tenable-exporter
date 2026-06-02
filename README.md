# tenable-exporter

![tenable-exporter banner](assets/banner.png)

[![CI](https://github.com/polarpoint-io/tenable-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/polarpoint-io/tenable-exporter/actions/workflows/ci.yml)
[![CodeQL](https://github.com/polarpoint-io/tenable-exporter/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/polarpoint-io/tenable-exporter/actions/workflows/codeql-analysis.yml)
[![PyPI](https://img.shields.io/pypi/v/tenable-exporter?logo=pypi&logoColor=white)](https://pypi.org/project/tenable-exporter/)
[![Python](https://img.shields.io/pypi/pyversions/tenable-exporter?logo=python&logoColor=white)](https://pypi.org/project/tenable-exporter/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GHCR](https://img.shields.io/badge/ghcr.io-tenable--exporter-blue?logo=github)](https://github.com/polarpoint-io/tenable-exporter/pkgs/container/tenable-exporter)

A Prometheus exporter for [Tenable.io](https://www.tenable.com/) built with [pyTenable](https://github.com/tenable/pyTenable).

Exports vulnerability, asset, and scan metrics so you can alert on them in Grafana or any Prometheus-compatible stack.

> **PyPI**: `pip install tenable-exporter` &nbsp;·&nbsp; **Image**: `ghcr.io/polarpoint-io/tenable-exporter:latest` &nbsp;·&nbsp; **Repo**: <https://github.com/polarpoint-io/tenable-exporter>

## Metrics

### Vulnerabilities

| Metric | Labels | Description |
|---|---|---|
| `tenable_vulnerabilities_total` | `severity` | Total vulnerabilities by severity |
| `tenable_vulnerabilities_by_subscription_total` | `provider`, `subscription_id`, `severity` | Vulns per cloud provider and subscription |
| `tenable_vulnerabilities_by_region_total` | `provider`, `subscription_id`, `region`, `severity` | Vulns per subscription and region |
| `tenable_vulnerabilities_by_resource_group_total` | `provider`, `subscription_id`, `resource_group`, `severity` | Vulns per Azure resource group |
| `tenable_vulnerabilities_by_resource_total` | `provider`, `subscription_id`, `resource_id`, `severity` | Vulns per individual cloud resource |
| `tenable_vulnerabilities_by_plugin_family_total` | `plugin_family`, `severity` | Vulns by Tenable plugin family and severity |
| `tenable_vulnerabilities_by_subscription_plugin_total` | `provider`, `subscription_id`, `region`, `plugin_family`, `severity` | Cross-dimension vuln count |
| `tenable_vulnerabilities_by_state_total` | `provider`, `subscription_id`, `state`, `severity` | Vulns by lifecycle state (`OPEN`, `REOPENED`, `FIXED`) — use `FIXED` to track remediation velocity |
| `tenable_vulnerabilities_by_exploit_risk_total` | `cve_category`, `severity` | Vulns by Tenable CVE category: `cisa known exploitable`, `ransomware`, `emerging threats`, `persistently exploited`, `top 50 vpr`, `recent active exploitation`, `in the news` |
| `tenable_vulnerabilities_by_vpr_band_total` | `provider`, `subscription_id`, `vpr_band` | Vulns by VPR (Vulnerability Priority Rating) band: `critical` (9–10), `high` (7–8.9), `medium` (4–6.9), `low` (<4) |

### Assets

| Metric | Labels | Description |
|---|---|---|
| `tenable_assets_by_subscription_total` | `provider`, `subscription_id` | Asset count per cloud provider and subscription |
| `tenable_assets_by_region_total` | `provider`, `subscription_id`, `region` | Asset count per subscription and region |
| `tenable_assets_by_resource_group_total` | `provider`, `subscription_id`, `resource_group` | Asset count per Azure resource group |
| `tenable_assets_by_resource_type_total` | `provider`, `subscription_id`, `region`, `resource_type` | Asset count by resource type (e.g. `t3.medium`, `Standard_D2s_v3`) |
| `tenable_assets_by_source_total` | `source` | Assets by Tenable discovery source (`AWS`, `AZURE`, `GCP`, `NESSUS`, `WAS`, …) |
| `tenable_assets_by_tag_total` | `tag_category`, `tag_value` | Assets by Tenable tag or cloud-native resource tag. Use `tag_category=asset_type` with values like `database`, `container_registry`, `acr`, `aks`, `rds` to track specific resource classes |

### Compliance

| Metric | Labels | Description |
|---|---|---|
| `tenable_compliance_findings_total` | `provider`, `subscription_id`, `audit_name`, `result` | CIS/DISA STIG compliance findings by audit and result (`PASSED`, `FAILED`, `WARNING`, `SKIPPED`) |
| `tenable_compliance_findings_by_region_total` | `provider`, `subscription_id`, `region`, `result` | Compliance findings per region |
| `tenable_compliance_findings_by_resource_group_total` | `provider`, `subscription_id`, `resource_group`, `result` | Compliance findings per Azure resource group |

### Scans & System

| Metric | Labels | Description |
|---|---|---|
| `tenable_scans_total` | — | Total number of scans |
| `tenable_scans_by_status_total` | `status` | Scans by status (running, completed, aborted, …) |
| `tenable_plugin_set_updated_timestamp` | — | Unix timestamp of the last plugin set update |

### Label values by cloud provider

| Label | AWS | Azure | GCP |
|---|---|---|---|
| `provider` | `aws` | `azure` | `gcp` |
| `subscription_id` | Account ID | Subscription UUID | Project ID |
| `region` | e.g. `us-east-1` | Azure location | GCP zone |
| `resource_group` | `unknown` | Resource group name | `unknown` |
| `resource_id` | EC2 instance ID | Azure resource / VM ID | GCP instance ID |
| `resource_type` | EC2 instance type | VM size | Machine type |

### Targeting databases, ACRs, and other resource types

Tenable doesn't have a dedicated field for resource class (database, container registry, etc.). The recommended approaches:

**Option 1 — Tenable tags (most reliable):** In the Tenable UI, create a tag category `AssetType` and assign values like `database`, `acr`, `aks`, `rds`, `cosmos_db` to assets. These appear immediately in `tenable_assets_by_tag_total{tag_category="assettype"}`.

**Option 2 — Cloud-native resource tags:** Enable `include_resource_tags=True` (already on). Any AWS tag, Azure tag, or GCP label on the resource appears as a `tenable_assets_by_tag_total` time series. For example, an Azure ACR tagged `{"resource_type": "container_registry"}` surfaces as `tag_category="resource_type", tag_value="container_registry"`.

**Option 3 — Plugin family:** Database vulnerabilities land in the `Databases` plugin family — visible in `tenable_vulnerabilities_by_plugin_family_total{plugin_family="databases"}`.

**Option 4 — Discovery source filter:** Scope the exporter to specific sources via `TENABLE_FILTER_PROVIDERS`. For ACR-specific scanning, Tenable uses the `AZURE` source; container-specific findings come from the `Containers` plugin family.

## Quick start

### pip

```bash
pip install tenable-exporter
export TENABLE_ACCESS_KEY=your_access_key
export TENABLE_SECRET_KEY=your_secret_key

tenable-exporter
```

Metrics will be available at `http://localhost:9190/metrics`.

### Docker

```bash
docker run -p 9190:9190 \
  -e TENABLE_ACCESS_KEY=your_access_key \
  -e TENABLE_SECRET_KEY=your_secret_key \
  ghcr.io/polarpoint-io/tenable-exporter:latest
```

### Docker Compose

```bash
cp .env.example .env
# Fill in your Tenable credentials in .env
docker compose up -d
```

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `TENABLE_ACCESS_KEY` | **required** | Tenable.io API access key |
| `TENABLE_SECRET_KEY` | **required** | Tenable.io API secret key |
| `EXPORTER_PORT` | `9190` | Port to expose metrics on |
| `SCRAPE_INTERVAL` | `300` | Seconds between Tenable API scrapes |
| `TENABLE_FILTER_PROVIDERS` | _(all)_ | Comma-separated providers to include: `aws`, `azure`, `gcp` |
| `TENABLE_FILTER_SUBSCRIPTIONS` | _(all)_ | Comma-separated subscription IDs to include (AWS account IDs, Azure subscription UUIDs, or GCP project IDs) |

## Docker image tags

| Tag | When pushed |
|---|---|
| `latest` | Every merge to `main` |
| `sha-<short>` | Every merge to `main` |
| `1.2.3` / `1.2` | On a semantic-release version bump |

## Required GitHub secrets

Add these at **GitHub repo → Settings → Secrets and variables → Actions**:

| Secret | Description |
|---|---|
| `POL_GH_TOKEN` | Personal access token with `repo` + `write:packages` scope |
| `PYPI_TOKEN` | PyPI API token for the `tenable-exporter` project |

## Development

```bash
git clone https://github.com/polarpoint-io/tenable-exporter.git
cd tenable-exporter
pip install -e ".[dev]"

export TENABLE_ACCESS_KEY=...
export TENABLE_SECRET_KEY=...

tenable-exporter
```

## License

MIT — see [LICENSE](LICENSE).
