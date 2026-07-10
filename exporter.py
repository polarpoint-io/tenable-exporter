"""
Tenable Prometheus Exporter

Exports Tenable.io metrics as Prometheus-compatible metrics with full
per-cloud-provider / subscription / region / resource granularity, plus
exploit-risk, compliance, asset-tag, VPR-band, and state-tracking metrics.

Subscription semantics per provider
────────────────────────────────────
  AWS   → subscription_id = aws_owner_id
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
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
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

# Tenable severity_id / severity_default_id → label (0=info … 4=critical)
_SEVERITY_LABELS = ("info", "low", "medium", "high", "critical")

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

def _csv_env(key: str, *, lower: bool = False) -> set[str]:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return set()
    values = [v.strip() for v in raw.split(",") if v.strip()]
    return {v.lower() for v in values} if lower else set(values)


_AZURE_SUB_RE = re.compile(r"/subscriptions/([^/]+)", re.I)
_AZURE_RG_RE = re.compile(r"/resourceGroups/([^/]+)", re.I)


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


def _first_str(*values: Any) -> str:
    for value in values:
        s = _str(value)
        if s != UNKNOWN:
            return s
    return UNKNOWN


def _asset_uid(record: dict[str, Any]) -> str:
    """Return the Tenable asset UUID from an asset or finding record.

  Asset exports use top-level ``id``. Vulnerability exports reference
  ``asset.uuid``; compliance exports use ``asset.id``. Prefer the nested
  asset object so a finding-level identifier is never mistaken for an asset id.
    """
    asset = record.get("asset")
    if isinstance(asset, dict):
        for candidate in (asset.get("uuid"), asset.get("id")):
            uid = _str(candidate)
            if uid != UNKNOWN:
                return uid
    for candidate in (record.get("id"), record.get("uuid")):
        uid = _str(candidate)
        if uid != UNKNOWN:
            return uid
    return ""


def _normalize_severity(vuln: dict[str, Any]) -> str:
    """Map Tenable severity strings or numeric severity_id values to a label."""
    raw = vuln.get("severity")
    if raw is not None:
        sev = str(raw).strip().lower()
        if sev in _SEVERITY_LABELS:
            return sev
        if sev.isdigit():
            idx = int(sev)
            if 0 <= idx < len(_SEVERITY_LABELS):
                return _SEVERITY_LABELS[idx]
    for key in ("severity_id", "severity_default_id"):
        val = vuln.get(key)
        if val is None:
            continue
        try:
            idx = int(val)
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(_SEVERITY_LABELS):
            return _SEVERITY_LABELS[idx]
    return _str(raw).lower() if raw is not None else UNKNOWN


def _compliance_result(finding: dict[str, Any]) -> str:
    return _str(
        finding.get("status")
        or finding.get("compliance_result")
        or finding.get("result")
    ).upper()


def _compliance_audit_name(finding: dict[str, Any]) -> str:
    return _str(
        finding.get("audit_name")
        or finding.get("compliance_benchmark_name")
        or finding.get("check_name")
        or finding.get("audit_file")
    ).lower()


def _provider_from_sources(asset: dict[str, Any]) -> str:
    sources = asset.get("sources") or []
    for src in sources:
        name = _str(src.get("name")).lower()
        if name in {"aws", "azure", "gcp"}:
            return name
        if "aws" in name:
            return "aws"
        if "azure" in name:
            return "azure"
        if "gcp" in name:
            return "gcp"
    if sources:
        return _str(sources[0].get("name")).lower()
    return UNKNOWN


def _iter_asset_tags(asset: dict[str, Any]):
    """Yield (category, value) from Tenable tags and cloud resource_tags."""
    for tag in asset.get("tags") or []:
        cat = _str(tag.get("tag_key") or tag.get("key") or tag.get("category")).lower()
        val = _str(tag.get("tag_value") or tag.get("value")).lower()
        if cat != UNKNOWN:
            yield cat, val
    for tag in asset.get("resource_tags") or []:
        cat = _str(tag.get("key")).lower()
        val = _str(tag.get("value")).lower()
        if cat != UNKNOWN:
            yield cat, val


_CLOUD_CONTEXT_DIMENSIONS = ("subscription_id", "region", "resource_group")


def _cloud_context_stats(ctx: AssetCloud) -> dict[tuple[str, str], int]:
    """Return {(dimension, status): 1} tallies for known vs unknown cloud labels."""
    stats: dict[tuple[str, str], int] = {}
    for dimension in _CLOUD_CONTEXT_DIMENSIONS:
        value = getattr(ctx, dimension)
        status = "unknown" if value == UNKNOWN else "known"
        stats[(dimension, status)] = 1
    return stats


def _parse_plugin_set_value(raw: Any) -> float:
    """Parse plugin set stamps from YYYYMMDDHHMM, Unix seconds, or ISO-8601."""
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        value = float(raw)
        if value > 1_000_000_000:
            return value
        raw = str(int(value))
    else:
        raw = str(raw).strip()
    if not raw:
        return 0.0
    if raw.isdigit():
        if len(raw) >= 12:
            dt = datetime.strptime(raw[:12], "%Y%m%d%H%M").replace(tzinfo=UTC)
            return dt.timestamp()
        if len(raw) == 10:
            return float(raw)
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except ValueError:
        return 0.0


def _plugin_set_timestamp(tio: TenableIO) -> float:
    """Return Unix timestamp of the last Tenable plugin set update."""
    for source, keys in (
        ("properties", ("loaded_plugin_set", "plugin_set")),
        ("status", ("plugins_expiration_date", "plugin_set_updated")),
    ):
        try:
            data = (
                tio.server.properties()
                if source == "properties"
                else tio.server.status()
            )
        except Exception as exc:
            log.warning("Plugin set timestamp from server %s unavailable: %s", source, exc)
            continue
        for key in keys:
            ts = _parse_plugin_set_value(data.get(key))
            if ts > 0:
                return ts
    return 0.0


def _vpr_score_from_vuln(vuln: dict[str, Any]) -> float | None:
    plugin = vuln.get("plugin") or {}
    candidates: list[Any] = []
    for key in ("vpr", "vpr_v2"):
        data = plugin.get(key)
        if isinstance(data, dict):
            candidates.append(data.get("score"))
    candidates.append(plugin.get("vpr_score"))
    top_vpr = vuln.get("vpr")
    if isinstance(top_vpr, dict):
        candidates.append(top_vpr.get("score"))
    for raw in candidates:
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def cloud_from_asset(asset: dict[str, Any]) -> AssetCloud:
    ctx = AssetCloud()
    cloud = asset.get("cloud") if isinstance(asset.get("cloud"), dict) else {}
    aws_cloud = cloud.get("aws") if isinstance(cloud.get("aws"), dict) else {}
    az_cloud  = cloud.get("azure") if isinstance(cloud.get("azure"), dict) else {}
    gcp_cloud = cloud.get("gcp") if isinstance(cloud.get("gcp"), dict) else {}
    common_cloud = cloud.get("common") if isinstance(cloud.get("common"), dict) else {}

    aws_account = _first_str(
        asset.get("aws_owner_id"),
        asset.get("aws_account_id"),  # legacy / misnamed callers
        aws_cloud.get("owner_id"),
    )
    az_sub = _first_str(
        asset.get("azure_subscription_id"),
        az_cloud.get("subscription_id"),
    )
    gcp_project = _first_str(
        asset.get("gcp_project_id"),
        gcp_cloud.get("project_id"),
    )

    azure_resource_id = _first_str(
        asset.get("azure_resource_id"),
        asset.get("azure_vm_id"),
        az_cloud.get("resource_id"),
        az_cloud.get("vm_id"),
    )
    if az_sub == UNKNOWN and azure_resource_id != UNKNOWN:
        match = _AZURE_SUB_RE.search(azure_resource_id)
        if match:
            az_sub = match.group(1)
    azure_resource_group = _first_str(
        asset.get("azure_resource_group"),
        az_cloud.get("resource_group"),
    )
    if azure_resource_group == UNKNOWN and azure_resource_id != UNKNOWN:
        match = _AZURE_RG_RE.search(azure_resource_id)
        if match:
            azure_resource_group = match.group(1)

    if aws_account != UNKNOWN:
        ctx.provider        = "aws"
        ctx.subscription_id = aws_account
        ctx.region          = _first_str(asset.get("aws_region"), aws_cloud.get("region"))
        ctx.resource_id     = _first_str(
            asset.get("aws_ec2_instance_id"),
            aws_cloud.get("ec2_instance_id"),
        )
        ctx.resource_type   = _first_str(
            asset.get("aws_ec2_instance_type"),
            aws_cloud.get("ec2_instance_type"),
        )
        ctx.vpc_id          = _first_str(asset.get("aws_vpc_id"), aws_cloud.get("vpc_id"))
    elif az_sub != UNKNOWN or azure_resource_id != UNKNOWN:
        ctx.provider        = "azure"
        ctx.subscription_id = az_sub
        ctx.region          = _first_str(
            asset.get("azure_location"),
            az_cloud.get("location"),
            az_cloud.get("region"),
        )
        ctx.resource_group  = azure_resource_group
        ctx.resource_id     = azure_resource_id
        ctx.resource_type   = _first_str(asset.get("azure_vm_size"), az_cloud.get("vm_size"))
        ctx.vpc_id          = _first_str(
            asset.get("azure_virtual_network"),
            az_cloud.get("virtual_network"),
        )
    elif gcp_project != UNKNOWN:
        ctx.provider        = "gcp"
        ctx.subscription_id = gcp_project
        ctx.region          = _first_str(asset.get("gcp_zone"), gcp_cloud.get("zone"))
        ctx.resource_id     = _first_str(
            asset.get("gcp_instance_id"),
            gcp_cloud.get("instance_id"),
        )
        ctx.resource_type   = _first_str(
            asset.get("gcp_machine_type"),
            gcp_cloud.get("machine_type"),
        )
        ctx.vpc_id          = _first_str(asset.get("gcp_network"), gcp_cloud.get("network"))
    else:
        ctx.provider = _provider_from_sources(asset)

    if common_cloud:
        common_provider = _str(common_cloud.get("provider")).lower()
        if ctx.subscription_id == UNKNOWN:
            ctx.subscription_id = _first_str(
                common_cloud.get("subscription_id"),
                common_cloud.get("account_id"),
                common_cloud.get("project_id"),
            )
        if ctx.region == UNKNOWN:
            ctx.region = _first_str(
                common_cloud.get("region"),
                common_cloud.get("location"),
                common_cloud.get("zone"),
            )
        if ctx.resource_group == UNKNOWN:
            ctx.resource_group = _first_str(common_cloud.get("resource_group"))
        if ctx.provider == UNKNOWN and common_provider not in {UNKNOWN, ""}:
            ctx.provider = common_provider

    if ctx.provider == UNKNOWN:
        cloud_source = _str(asset.get("cloud_source")).lower()
        if cloud_source in {"aws", "azure", "gcp"}:
            ctx.provider = cloud_source
        elif "azure" in cloud_source:
            ctx.provider = "azure"
        elif "aws" in cloud_source:
            ctx.provider = "aws"
        elif "gcp" in cloud_source or "google" in cloud_source:
            ctx.provider = "gcp"

    network = asset.get("network") if isinstance(asset.get("network"), dict) else {}
    ctx.network_name = _first_str(asset.get("network_name"), network.get("network_name"))
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

    def _reset_diagnostics(self) -> None:
        self._cloud_context_by_entity: dict[tuple[str, str, str, str], int] = {}
        self._vuln_asset_lookup_misses = 0
        self._vuln_vpr_unknown          = 0

    def _record_cloud_context(self, entity: str, ctx: AssetCloud) -> None:
        for (dimension, status), n in _cloud_context_stats(ctx).items():
            key = (entity, ctx.provider, dimension, status)
            self._cloud_context_by_entity[key] = (
                self._cloud_context_by_entity.get(key, 0) + n
            )

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
            for asset in self.tio.exports.assets_v2(include_resource_tags=True):
                uid = _asset_uid(asset)
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

                # Tenable tags + cloud-native resource tags (assets v2 resource_tags)
                for cat, val in _iter_asset_tags(asset):
                    k = (cat, val)
                    by_tag[k] = by_tag.get(k, 0) + 1

                self._record_cloud_context("asset", ctx)

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

        asset_lookup_misses = 0

        try:
            for vuln in self.tio.exports.vulns(
                severity=["critical", "high", "medium", "low", "info"],
                state=["OPEN", "REOPENED", "FIXED"],
                include_unlicensed=True,
            ):
                sev    = _normalize_severity(vuln)
                state  = _str(vuln.get("state")).upper()
                family = _str(vuln.get("plugin", {}).get("family")).lower()

                vpr_score = _vpr_score_from_vuln(vuln)
                band = _vpr_band(vpr_score)

                # CVE categories (list field on each finding)
                cve_categories = vuln.get("plugin", {}).get("cve_category") or []
                if not cve_categories:
                    cve_categories = [UNKNOWN]

                asset_uid = _asset_uid(vuln)
                ctx = asset_map.get(asset_uid, AssetCloud())
                if asset_uid and asset_uid not in asset_map:
                    asset_lookup_misses += 1

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

                if band == UNKNOWN:
                    self._vuln_vpr_unknown += 1

                self._record_cloud_context("vulnerability", ctx)

        except Exception as exc:
            log.warning("Vulnerability collection error: %s", exc)

        if asset_lookup_misses:
            log.warning(
                "Vulnerability asset lookup misses: %d (cloud labels may show %r)",
                asset_lookup_misses,
                UNKNOWN,
            )
        self._vuln_asset_lookup_misses = asset_lookup_misses

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
                result = _compliance_result(finding)
                audit  = _compliance_audit_name(finding)
                asset_uid = _asset_uid(finding)
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
        self._reset_diagnostics()
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
        yield from self._emit_diagnostic_metrics()

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
            ts = _plugin_set_timestamp(self.tio)
        except Exception:
            ts = 0
        m.add_metric([], ts)
        yield m

    def _emit_diagnostic_metrics(self):
        m = GaugeMetricFamily(
            "tenable_exporter_cloud_context_total",
            "Assets or vulnerabilities with known vs unknown cloud context labels. "
            "Use to track whether Tenable is exporting subscription, region, and "
            "resource group metadata. High unknown counts on vulnerability entity "
            "usually indicate missing Azure/AWS connector data or asset join misses.",
            labels=["entity", "provider", "dimension", "status"],
        )
        for (entity, prov, dimension, status), n in self._cloud_context_by_entity.items():
            m.add_metric([entity, prov, dimension, status], n)
        yield m

        m = GaugeMetricFamily(
            "tenable_exporter_vulnerability_asset_lookup_misses_total",
            "Vulnerabilities whose asset UUID was not found in the asset export index",
        )
        m.add_metric([], self._vuln_asset_lookup_misses)
        yield m

        m = GaugeMetricFamily(
            "tenable_exporter_vulnerability_vpr_unknown_total",
            "Vulnerabilities with no VPR score assigned by Tenable (expected for "
            "info findings and plugins without threat intelligence)",
        )
        m.add_metric([], self._vuln_vpr_unknown)
        yield m


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    access_key  = os.environ["TENABLE_ACCESS_KEY"]
    secret_key  = os.environ["TENABLE_SECRET_KEY"]
    port            = int(os.environ.get("EXPORTER_PORT", "9190"))
    scrape_interval = int(os.environ.get("SCRAPE_INTERVAL", "300"))

    filter_providers     = _csv_env("TENABLE_FILTER_PROVIDERS", lower=True)
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
