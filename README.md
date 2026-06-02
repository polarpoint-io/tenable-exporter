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

| Metric | Labels | Description |
|---|---|---|
| `tenable_vulnerabilities_total` | `severity` | Total vulnerabilities by severity (critical/high/medium/low/info) |
| `tenable_vulnerabilities_by_plugin_total` | `plugin_family` | Vulnerabilities grouped by plugin family |
| `tenable_assets_total` | — | Total number of assets |
| `tenable_assets_by_source_total` | `source` | Assets grouped by discovery source |
| `tenable_scans_total` | — | Total number of scans |
| `tenable_scans_by_status_total` | `status` | Scans grouped by status |
| `tenable_plugin_set_updated_timestamp` | — | Unix timestamp of the last plugin set update |

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
