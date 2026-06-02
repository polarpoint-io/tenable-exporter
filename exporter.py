"""
Tenable Prometheus Exporter

Exports Tenable.io metrics as Prometheus-compatible metrics.
"""

import logging
import os
import time

from prometheus_client import (
    Gauge,
    Counter,
    start_http_server,
    REGISTRY,
    CollectorRegistry,
)
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from tenable.io import TenableIO

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("tenable_exporter")


class TenableCollector:
    """Custom Prometheus collector for Tenable.io metrics."""

    def __init__(self, tio: TenableIO):
        self.tio = tio

    def collect(self):
        log.info("Collecting Tenable metrics...")

        # ── Vulnerability metrics ──────────────────────────────────────────
        vuln_by_severity = GaugeMetricFamily(
            "tenable_vulnerabilities_total",
            "Total number of vulnerabilities by severity",
            labels=["severity"],
        )
        vuln_by_plugin = GaugeMetricFamily(
            "tenable_vulnerabilities_by_plugin_total",
            "Total vulnerabilities grouped by plugin family",
            labels=["plugin_family"],
        )

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        plugin_family_counts: dict[str, int] = {}

        try:
            for vuln in self.tio.exports.vulns(severity=["critical", "high", "medium", "low", "info"]):
                sev = vuln.get("severity", "info").lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

                family = vuln.get("plugin", {}).get("family", "unknown")
                plugin_family_counts[family] = plugin_family_counts.get(family, 0) + 1
        except Exception as e:
            log.warning("Failed to collect vulnerability data: %s", e)

        for sev, count in severity_counts.items():
            vuln_by_severity.add_metric([sev], count)
        yield vuln_by_severity

        for family, count in plugin_family_counts.items():
            vuln_by_plugin.add_metric([family], count)
        yield vuln_by_plugin

        # ── Asset metrics ──────────────────────────────────────────────────
        asset_total = GaugeMetricFamily(
            "tenable_assets_total",
            "Total number of assets",
        )
        asset_by_source = GaugeMetricFamily(
            "tenable_assets_by_source_total",
            "Assets grouped by discovery source",
            labels=["source"],
        )

        asset_count = 0
        source_counts: dict[str, int] = {}

        try:
            for asset in self.tio.exports.assets():
                asset_count += 1
                for source in asset.get("sources", [{"name": "unknown"}]):
                    s = source.get("name", "unknown")
                    source_counts[s] = source_counts.get(s, 0) + 1
        except Exception as e:
            log.warning("Failed to collect asset data: %s", e)

        asset_total.add_metric([], asset_count)
        yield asset_total

        for source, count in source_counts.items():
            asset_by_source.add_metric([source], count)
        yield asset_by_source

        # ── Scan metrics ───────────────────────────────────────────────────
        scan_total = GaugeMetricFamily(
            "tenable_scans_total",
            "Total number of scans",
        )
        scan_by_status = GaugeMetricFamily(
            "tenable_scans_by_status_total",
            "Scans grouped by status",
            labels=["status"],
        )

        scan_count = 0
        scan_status_counts: dict[str, int] = {}

        try:
            for scan in self.tio.scans.list():
                scan_count += 1
                status = scan.get("status", "unknown")
                scan_status_counts[status] = scan_status_counts.get(status, 0) + 1
        except Exception as e:
            log.warning("Failed to collect scan data: %s", e)

        scan_total.add_metric([], scan_count)
        yield scan_total

        for status, count in scan_status_counts.items():
            scan_by_status.add_metric([status], count)
        yield scan_by_status

        # ── Plugin update timestamp ────────────────────────────────────────
        plugin_update = GaugeMetricFamily(
            "tenable_plugin_set_updated_timestamp",
            "Unix timestamp of the last plugin set update",
        )
        try:
            info = self.tio.editor.plugin_families()
            # plugin_families returns a list; grab the most recent updated_at if available
            # Fallback: use server status
            status = self.tio.server.status()
            ts = status.get("plugins_expiration_date", 0)
            plugin_update.add_metric([], ts)
        except Exception as e:
            log.warning("Failed to collect plugin update timestamp: %s", e)
            plugin_update.add_metric([], 0)
        yield plugin_update

        log.info("Metric collection complete.")


def main():
    access_key = os.environ["TENABLE_ACCESS_KEY"]
    secret_key = os.environ["TENABLE_SECRET_KEY"]
    port = int(os.environ.get("EXPORTER_PORT", "9190"))
    scrape_interval = int(os.environ.get("SCRAPE_INTERVAL", "300"))

    tio = TenableIO(access_key, secret_key)

    registry = CollectorRegistry()
    registry.register(TenableCollector(tio))

    start_http_server(port, registry=registry)
    log.info("Tenable exporter listening on :%d", port)

    while True:
        time.sleep(scrape_interval)


if __name__ == "__main__":
    main()
