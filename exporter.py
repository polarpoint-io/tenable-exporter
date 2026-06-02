"""
Tenable Prometheus Exporter

Exports Tenable.io metrics as Prometheus-compatible metrics with full
per-cloud-provider / subscription / region / resource granularity, plus
exploit-risk, compliance, asset-tag, VPR-band, and state-tracking metrics.

Subscription semantics per provider
────────────────────────────────────
  AWS   → subscription_id = aws_account_id
  Azure → subscription_id = azure_subscription_id
  GCP   → subscription_id = gcp_project_id

Environment variables
─────────────────────
  TENABLE_ACCESS_KEY            required
  TENABLE_SECRET_KEY            required
  EXPORTER_PORT                 default 9190
  SCRAPE_INTERVAL               default 300 (seconds)
  TENABLE_FILTER_PROVIDERS      comma-separated: aws,azure,gcp
  TENABLE_FILTER_SUBSCRIPTIONS  comma-separated subscription/account/project IDs
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from prometheus_client import CollectorRegistry, start_http_server
from prometheus_client.core import GaugeMetricFamily
from tenable.io import TenableIO

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("tenable_exporter")

UNKNOWN = "unknown"

# VPR score → band label
VPR_BANDS = [
    (9.0, "critical"),   # 9.0 – 10.0
    (7.0, "high"),       # 7.0 – 8.9
    (4.0, "medium"),     # 4.0 – 6.9
    (0.0, "low"),        # 0.0 – 3.9
]


def _vpr_band(score: float | None) -> str:
    if score is None:
        return UNKNOWN
    for threshold, label in VPR_BANDS:
        if score >= threshold:
            return label
    return "low"


# ── Config helpers ────────────────────────────────────────────────────────────

def _csv_env(key: str) -> set[str]:
    raw = os.environ.get(key, "").strip()
    return {v.strip().lower() for v in raw.split(",") if v.strip()} if raw else set()


# ── Cloud context ─────────────────────────────────────────────────────────────

@dataclass
class AssetCloud:
    """Normalised cloud context for one Tenable asset."""
    provider: str = UNKNOWN
    subscription_id: str = UNKNOWN  # AWS account / Azure subscription / GCP project
    region: str = UNKNOWN           # AWS region / Azure location / GCP zone
    resource_group: str = UNKNOWN   # Azure resource group (UNKNOWN for AWS/GCP)
    resource_id: str = UNKNOWN      # EC2 id / Azure resource id / GCP instance id
    resource_type: str = UNKNOWN    # EC2 type / Azure VM size / GCP machine type
    vpc_id: str = UNKNOWN
    network_name: str = UNKNOWN


def _str(v: Any) -> str:
    s = str(v).strip() if v else ""
    return s if s else UNKNOWN


def cloud_from_asset(asset: dict[str, Any]) -> AssetCloud:
    ctx = AssetCloud()
    aws = asset.get("aws_account_id")
    az  = asset.get("azure_subscription_id")
    gcp = asset.get("gcp_project_id")

    if aws:
        ctx.provider        = "aws"
        ctx.subscription_id = _str(aws)
        ctx.region          = _str(asset.get("aws_region"))
        ctx.resource_id     = _str(asset.get("aws_ec2_instance_id"))
        ctx.resource_type   = _str(asset.get("aws_ec2_instance_type"))
        ctx.vpc_id          = _str(asset.get("aws_vpc_id"))
    elif az:
        ctx.provider        = "azure"
        ctx.subscription_id = _str(az)
        ctx.region          = _str(asset.get("azure_location"))
        ctx.resource_group  = _str(asset.get("azure_resource_group"))
        ctx.resource_id     = _str(asset.get("azure_resource_id") or asset.get("azure_vm_id"))
        ctx.resource_type   = _str(asset.get("azure_vm_size"))
        ctx.vpc_id          = _str(asset.get("azure_virtual_network"))
    elif gcp:
        ctx.provider        = "gcp"
        ctx.subscription_id = _str(gcp)
        ctx.region          = _str(asset.get("gcp_zone"))
        ctx.resource_id     = _str(asset.get("gcp_instance_id"))
        ctx.resource_type   = _str(asset.get("gcp_machine_type"))
        ctx.vpc_id          = _str(asset.get("gcp_network"))
    else:
        sources = asset.get("sources", [])
        if sources:
            ctx.provider = _str(sources[0].get("name")).lower()

    ctx.network_name = _str(asset.get("network_name"))
    return ctx


# ── Collector ─────────────────────────────────────────────────────────────────

class TenableCollector:

    def __init__(
        self,
        tio: TenableIO,
        filter_providers: set[str],
        filter_subscriptions: set[str],
    ) -> None:
        self.tio = tio
        self._filter_providers     = filter_providers
        self._filter_subscriptions = filter_subscriptions

    def _include(self, ctx: AssetCloud) -> bool:
        if self._filter_providers and ctx.provider not in self._filter_providers:
            return False
        if self._filter_subscriptions and ctx.subscription_id not in self._filter_subscriptions:
            return False
        return True

    # ── assets ────────────────────────────────────────────────────────────────

    def _collect_assets(self) -> dict[str, AssetCloud]:
        log.info("Collecting assets …")
        asset_map: dict[str, AssetCloud] = {}

        by_subscription:   dict[tuple, int] = {}
        by_region:         dict[tuple, int] = {}
        by_resource_group: dict[tuple, int] = {}
        by_resource_type:  dict[tuple, int] = {}
        by_source:         dict[str, int]   = {}
        # (tag_category, tag_value)
        by_tag:            dict[tuple, int] = {}

        try:
            for asset in self.tio.exports.assets(include_resource_tags=True):
                uid = asset.get("id", "")
                ctx = cloud_from_asset(asset)
                if uid:
                    asset_map[uid] = ctx

                if not self._include(ctx):
                    continue

                k_sub = (ctx.provider, ctx.subscription_id)
                k_reg = (*k_sub, ctx.region)
                k_grp = (*k_sub, ctx.resource_group)
                k_rt  = (*k_reg, ctx.resource_type)

                by_subscription[k_sub]   = by_subscription.get(k_sub, 0) + 1
                by_region[k_reg]         = by_region.get(k_reg, 0) + 1
                by_resource_group[k_grp] = by_resource_group.get(k_grp, 0) + 1
                by_resource_type[k_rt]   = by_resource_type.get(k_rt, 0) + 1

                for src in asset.get("sources", [{"name": UNKNOWN}]):
                    s = _str(src.get("name")).lower()
                    by_source[s] = by_source.get(s, 0) + 1

                # Tenable tags + cloud-native resource tags
                for tag in asset.get("tags", []):
                    cat = _str(tag.get("tag_key") or tag.get("category")).lower()
                    val = _str(tag.get("tag_value") or tag.get("value")).lower()
                    if cat != UNKNOWN:
                        k = (cat, val)
                        by_tag[k] = by_tag.get(k, 0) + 1

        except Exception as exc:
            log.warning("Asset collection error: %s", exc)

        self._asset_by_subscription   = by_subscription
        self._asset_by_region         = by_region
        self._asset_by_resource_group = by_resource_group
        self._asset_by_resource_type  = by_resource_type
        self._asset_by_source         = by_source
        self._asset_by_tag            = by_tag
        log.info("Assets indexed: %d", len(asset_map))
        return asset_map

    # ── vulnerabilities ───────────────────────────────────────────────────────

    def _collect_vulns(self, asset_map: dict[str, AssetCloud]) -> None:
        log.info("Collecting vulnerabilities …")

        by_severity:            dict[str, int]   = {}
        by_subscription:        dict[tuple, int] = {}
        by_region:              dict[tuple, int] = {}
        by_resource_group:      dict[tuple, int] = {}
        by_resource:            dict[tuple, int] = {}
        by_plugin_family:       dict[tuple, int] = {}
        by_subscription_plugin: dict[tuple, int] = {}
        # state tracking  (provider, subscription_id, state, severity)
        by_state:               dict[tuple, int] = {}
        # exploit risk  (cve_category, severity)
        by_exploit_risk:        dict[tuple, int] = {}
        # VPR band  (provider, subscription_id, vpr_band)
        by_vpr_band:            dict[tuple, int] = {}

        try:
            for vuln in self.tio.exports.vulns(
                severity=["critical", "high", "medium", "low", "info"],
                state=["OPEN", "REOPENED", "FIXED"],
            ):
                sev    = _str(vuln.get("severity")).lower()
                state  = _str(vuln.get("state")).upper()
                family = _str(vuln.get("plugin", {}).get("family")).lower()

                # VPR score lives at plugin.vpr.score
                vpr_score = None
                vpr_data  = vuln.get("plugin", {}).get("vpr")
                if isinstance(vpr_data, dict):
                    vpr_score = vpr_data.get("score")
                    try:
                        vpr_score = float(vpr_score) if vpr_score is not None else None
                    except (TypeError, ValueError):
                        vpr_score = None
                band = _vpr_band(vpr_score)

                # CVE categories (list field on each finding)
                cve_categories = vuln.get("plugin", {}).get("cve_category") or []
                if not cve_categories:
                    cve_categories = [UNKNOWN]

                asset_uid = vuln.get("asset", {}).get("uuid", "")
                ctx = asset_map.get(asset_uid, AssetCloud())

                if not self._include(ctx):
                    continue

                by_severity[sev] = by_severity.get(sev, 0) + 1

                k_sub = (ctx.provider, ctx.subscription_id, sev)
                by_subscription[k_sub] = by_subscription.get(k_sub, 0) + 1

                k_reg = (ctx.provider, ctx.subscription_id, ctx.region, sev)
                by_region[k_reg] = by_region.get(k_reg, 0) + 1

                k_grp = (ctx.provider, ctx.subscription_id, ctx.resource_group, sev)
                by_resource_group[k_grp] = by_resource_group.get(k_grp, 0) + 1

                k_res = (ctx.provider, ctx.subscription_id, ctx.resource_id, sev)
                by_resource[k_res] = by_resource.get(k_res, 0) + 1

                k_pf = (family, sev)
                by_plugin_family[k_pf] = by_plugin_family.get(k_pf, 0) + 1

                k_sp = (ctx.provider, ctx.subscription_id, ctx.region, family, sev)
                by_subscription_plugin[k_sp] = by_subscription_plugin.get(k_sp, 0) + 1

                k_st = (ctx.provider, ctx.subscription_id, state, sev)
                by_state[k_st] = by_state.get(k_st, 0) + 1

                for cat in cve_categories:
                    k_er = (_str(cat).lower(), sev)
                    by_exploit_risk[k_er] = by_exploit_risk.get(k_er, 0) + 1

                k_vpr = (ctx.provider, ctx.subscription_id, band)
                by_vpr_band[k_vpr] = by_vpr_band.get(k_vpr, 0) + 1

        except Exception as exc:
            log.warning("Vulnerability collection error: %s", exc)

        self._vuln_by_severity            = by_severity
        self._vuln_by_subscription        = by_subscription
        self._vuln_by_region              = by_region
        self._vuln_by_resource_group      = by_resource_group
        self._vuln_by_resource            = by_resource
        self._vuln_by_plugin_family       = by_plugin_family
        self._vuln_by_subscription_plugin = by_subscription_plugin
        self._vuln_by_state               = by_state
        self._vuln_by_exploit_risk        = by_exploit_risk
        self._vuln_by_vpr_band            = by_vpr_band

    # ── compliance ────────────────────────────────────────────────────────────

    def _collect_compliance(self, asset_map: dict[str, AssetCloud]) -> None:
        log.info("Collecting compliance findings …")

        # (provider, subscription_id, audit_name, result)
        by_result:       dict[tuple, int] = {}
        # (provider, subscription_id, region, result)
        by_region:       dict[tuple, int] = {}
        # (provider, subscription_id, resource_group, result)
        by_resource_group: dict[tuple, int] = {}

        try:
            for finding in self.tio.exports.compliance():
                result    = _str(finding.get("compliance_result") or
                                 finding.get("status") or
                                 finding.get("result")).upper()
                audit     = _str(finding.get("audit_name")).lower()
                asset_uid = finding.get("asset", {}).get("uuid", "")
                ctx = asset_map.get(asset_uid, AssetCloud())

                if not self._include(ctx):
                    continue

                k_res = (ctx.provider, ctx.subscription_id, audit, result)
                by_result[k_res] = by_result.get(k_res, 0) + 1

                k_reg = (ctx.provider, ctx.subscription_id, ctx.region, result)
                by_region[k_reg] = by_region.get(k_reg, 0) + 1

                k_grp = (ctx.provider, ctx.subscription_id, ctx.resource_group, result)
                by_resource_group[k_grp] = by_resource_group.get(k_grp, 0) + 1

        except Exception as exc:
            log.warning("Compliance collection error: %s", exc)

        self._compliance_by_result        = by_result
        self._compliance_by_region        = by_region
        self._compliance_by_resource_group = by_resource_group

    # ── scans ─────────────────────────────────────────────────────────────────

    def _collect_scans(self) -> None:
        log.info("Collecting scans …")
        by_status: dict[str, int] = {}
        total = 0
        try:
            for scan in self.tio.scans.list():
                total += 1
                status = _str(scan.get("status")).lower()
                by_status[status] = by_status.get(status, 0) + 1
        except Exception as exc:
            log.warning("Scan collection error: %s", exc)
        self._scan_total     = total
        self._scan_by_status = by_status

    # ── emit ──────────────────────────────────────────────────────────────────

    def collect(self):  # noqa: C901
        asset_map = self._collect_assets()
        self._collect_vulns(asset_map)
        self._collect_compliance(asset_map)
        self._collect_scans()

        # ── VULNERABILITY METRICS ─────────────────────────────────────────────

        _g = GaugeMetricFamily
        yield from self._emit_vuln_metrics()
        yield from self._emit_asset_metrics()
        yield from self._emit_compliance_metrics()
        yield from self._emit_scan_metrics()
        yield from self._emit_system_metrics()

        log.info("Metric collection complete.")

    # ── vulnerability metric emitters ─────────────────────────────────────────

    def _emit_vuln_metrics(self):
        m = GaugeMetricFamily(
            "tenable_vulnerabilities_total",
            "Total open vulnerabilities by severity",
            labels=["severity"],
        )
        for sev, n in self._vuln_by_severity.items():
            m.add_metric([sev], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_subscription_total",
            "Open vulnerabilities per cloud provider and subscription, by severity",
            labels=["provider", "subscription_id", "severity"],
        )
        for (prov, sub, sev), n in self._vuln_by_subscription.items():
            m.add_metric([prov, sub, sev], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_region_total",
            "Open vulnerabilities per subscription and region, by severity",
            labels=["provider", "subscription_id", "region", "severity"],
        )
        for (prov, sub, reg, sev), n in self._vuln_by_region.items():
            m.add_metric([prov, sub, reg, sev], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_resource_group_total",
            "Open vulnerabilities per subscription and resource group, by severity",
            labels=["provider", "subscription_id", "resource_group", "severity"],
        )
        for (prov, sub, grp, sev), n in self._vuln_by_resource_group.items():
            m.add_metric([prov, sub, grp, sev], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_resource_total",
            "Open vulnerabilities per individual cloud resource, by severity",
            labels=["provider", "subscription_id", "resource_id", "severity"],
        )
        for (prov, sub, res, sev), n in self._vuln_by_resource.items():
            m.add_metric([prov, sub, res, sev], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_plugin_family_total",
            "Open vulnerabilities by Tenable plugin family and severity",
            labels=["plugin_family", "severity"],
        )
        for (fam, sev), n in self._vuln_by_plugin_family.items():
            m.add_metric([fam, sev], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_subscription_plugin_total",
            "Open vulnerabilities by subscription, region, plugin family, and severity",
            labels=["provider", "subscription_id", "region", "plugin_family", "severity"],
        )
        for (prov, sub, reg, fam, sev), n in self._vuln_by_subscription_plugin.items():
            m.add_metric([prov, sub, reg, fam, sev], n)
        yield m

        # ── State tracking (OPEN / REOPENED / FIXED) ──────────────────────────
        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_state_total",
            "Vulnerabilities by lifecycle state (OPEN, REOPENED, FIXED), "
            "provider, subscription, and severity. Use FIXED to track remediation velocity.",
            labels=["provider", "subscription_id", "state", "severity"],
        )
        for (prov, sub, state, sev), n in self._vuln_by_state.items():
            m.add_metric([prov, sub, state, sev], n)
        yield m

        # ── Exploit risk / CVE category ───────────────────────────────────────
        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_exploit_risk_total",
            "Vulnerabilities by Tenable CVE category and severity. "
            "Categories: cisa known exploitable, ransomware, emerging threats, "
            "persistently exploited, top 50 vpr, recent active exploitation, in the news.",
            labels=["cve_category", "severity"],
        )
        for (cat, sev), n in self._vuln_by_exploit_risk.items():
            m.add_metric([cat, sev], n)
        yield m

        # ── VPR band ──────────────────────────────────────────────────────────
        m = GaugeMetricFamily(
            "tenable_vulnerabilities_by_vpr_band_total",
            "Vulnerabilities by Tenable VPR (Vulnerability Priority Rating) band "
            "per provider and subscription. Bands: critical (9-10), high (7-8.9), "
            "medium (4-6.9), low (<4).",
            labels=["provider", "subscription_id", "vpr_band"],
        )
        for (prov, sub, band), n in self._vuln_by_vpr_band.items():
            m.add_metric([prov, sub, band], n)
        yield m

    # ── asset metric emitters ─────────────────────────────────────────────────

    def _emit_asset_metrics(self):
        m = GaugeMetricFamily(
            "tenable_assets_by_subscription_total",
            "Total assets per cloud provider and subscription",
            labels=["provider", "subscription_id"],
        )
        for (prov, sub), n in self._asset_by_subscription.items():
            m.add_metric([prov, sub], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_assets_by_region_total",
            "Total assets per subscription and region",
            labels=["provider", "subscription_id", "region"],
        )
        for (prov, sub, reg), n in self._asset_by_region.items():
            m.add_metric([prov, sub, reg], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_assets_by_resource_group_total",
            "Total assets per subscription and resource group "
            "(Azure resource group; UNKNOWN for AWS/GCP)",
            labels=["provider", "subscription_id", "resource_group"],
        )
        for (prov, sub, grp), n in self._asset_by_resource_group.items():
            m.add_metric([prov, sub, grp], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_assets_by_resource_type_total",
            "Total assets by resource type within each subscription and region "
            "(e.g. t3.medium, Standard_D2s_v3, n2-standard-4)",
            labels=["provider", "subscription_id", "region", "resource_type"],
        )
        for (prov, sub, reg, rt), n in self._asset_by_resource_type.items():
            m.add_metric([prov, sub, reg, rt], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_assets_by_source_total",
            "Total assets by Tenable discovery source "
            "(AWS, AZURE, GCP, NESSUS, NESSUS_AGENT, WAS, PVS, SERVICENOW, …)",
            labels=["source"],
        )
        for src, n in self._asset_by_source.items():
            m.add_metric([src], n)
        yield m

        # ── Tag-based asset breakdown ─────────────────────────────────────────
        # Covers Tenable tags AND cloud-native resource tags (via include_resource_tags).
        # Use tag_category=asset_type / tag_value=database|container_registry|acr
        # to target specific resource classes without needing a dedicated Tenable field.
        m = GaugeMetricFamily(
            "tenable_assets_by_tag_total",
            "Total assets by Tenable tag category and value. "
            "Includes cloud-native tags (AWS tags, Azure tags, GCP labels). "
            "Use tag_category='asset_type' with values like 'database', "
            "'container_registry', 'acr', 'aks', 'rds' to track specific resource classes.",
            labels=["tag_category", "tag_value"],
        )
        for (cat, val), n in self._asset_by_tag.items():
            m.add_metric([cat, val], n)
        yield m

    # ── compliance metric emitters ────────────────────────────────────────────

    def _emit_compliance_metrics(self):
        # (provider, subscription_id, audit_name, result)
        m = GaugeMetricFamily(
            "tenable_compliance_findings_total",
            "Compliance findings per audit, provider, and subscription. "
            "Results: PASSED, FAILED, WARNING, SKIPPED, ERROR, UNKNOWN.",
            labels=["provider", "subscription_id", "audit_name", "result"],
        )
        for (prov, sub, audit, result), n in self._compliance_by_result.items():
            m.add_metric([prov, sub, audit, result], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_compliance_findings_by_region_total",
            "Compliance findings per subscription, region, and result",
            labels=["provider", "subscription_id", "region", "result"],
        )
        for (prov, sub, reg, result), n in self._compliance_by_region.items():
            m.add_metric([prov, sub, reg, result], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_compliance_findings_by_resource_group_total",
            "Compliance findings per subscription, resource group, and result "
            "(Azure resource group; UNKNOWN for AWS/GCP)",
            labels=["provider", "subscription_id", "resource_group", "result"],
        )
        for (prov, sub, grp, result), n in self._compliance_by_resource_group.items():
            m.add_metric([prov, sub, grp, result], n)
        yield m

    # ── scan + system emitters ────────────────────────────────────────────────

    def _emit_scan_metrics(self):
        m = GaugeMetricFamily("tenable_scans_total", "Total number of scans")
        m.add_metric([], self._scan_total)
        yield m

        m = GaugeMetricFamily(
            "tenable_scans_by_status_total",
            "Scans grouped by status",
            labels=["status"],
        )
        for status, n in self._scan_by_status.items():
            m.add_metric([status], n)
        yield m

    def _emit_system_metrics(self):
        m = GaugeMetricFamily(
            "tenable_plugin_set_updated_timestamp",
            "Unix timestamp of the last Tenable plugin set update",
        )
        try:
            ts = self.tio.server.status().get("plugins_expiration_date", 0)
        except Exception:
            ts = 0
        m.add_metric([], ts)
        yield m


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    access_key  = os.environ["TENABLE_ACCESS_KEY"]
    secret_key  = os.environ["TENABLE_SECRET_KEY"]
    port            = int(os.environ.get("EXPORTER_PORT", "9190"))
    scrape_interval = int(os.environ.get("SCRAPE_INTERVAL", "300"))

    filter_providers     = _csv_env("TENABLE_FILTER_PROVIDERS")
    filter_subscriptions = _csv_env("TENABLE_FILTER_SUBSCRIPTIONS")

    if filter_providers:
        log.info("Filtering to providers: %s", filter_providers)
    if filter_subscriptions:
        log.info("Filtering to subscriptions: %s", filter_subscriptions)

    tio = TenableIO(access_key, secret_key)

    registry = CollectorRegistry()
    registry.register(TenableCollector(tio, filter_providers, filter_subscriptions))

    start_http_server(port, registry=registry)
    log.info("Tenable exporter listening on :%d", port)

    while True:
        time.sleep(scrape_interval)


if __name__ == "__main__":
    main()
