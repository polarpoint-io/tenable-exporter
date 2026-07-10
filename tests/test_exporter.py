"""Unit tests for tenable-exporter."""

import pytest
from exporter import (
    AssetCloud,
    cloud_from_asset,
    _str,
    _vpr_band,
    _vpr_score_from_vuln,
    _asset_uid,
    _normalize_severity,
    _compliance_result,
    _compliance_audit_name,
    _parse_plugin_set_value,
    _iter_asset_tags,
    _cloud_context_stats,
    _plugin_set_timestamp,
    TenableCollector,
    UNKNOWN,
)


# ── _str ──────────────────────────────────────────────────────────────────────

def test_str_none():
    assert _str(None) == UNKNOWN


def test_str_empty():
    assert _str("") == UNKNOWN


def test_str_whitespace():
    assert _str("  ") == UNKNOWN


def test_str_value():
    assert _str("us-east-1") == "us-east-1"


def test_str_strips():
    assert _str("  hello  ") == "hello"


# ── _vpr_band ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (10.0,  "critical"),
    (9.0,   "critical"),
    (8.9,   "high"),
    (7.0,   "high"),
    (6.9,   "medium"),
    (4.0,   "medium"),
    (3.9,   "low"),
    (0.0,   "low"),
    (None,  UNKNOWN),
])
def test_vpr_band(score, expected):
    assert _vpr_band(score) == expected


# ── cloud_from_asset ──────────────────────────────────────────────────────────

def test_cloud_from_asset_aws():
    asset = {
        "id": "abc",
        "aws_owner_id": "123456789012",
        "aws_region": "us-east-1",
        "aws_ec2_instance_id": "i-0abc123",
        "aws_ec2_instance_type": "t3.medium",
        "aws_vpc_id": "vpc-001",
        "network_name": "default",
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "aws"
    assert ctx.subscription_id == "123456789012"
    assert ctx.region          == "us-east-1"
    assert ctx.resource_id     == "i-0abc123"
    assert ctx.resource_type   == "t3.medium"
    assert ctx.vpc_id          == "vpc-001"
    assert ctx.resource_group  == UNKNOWN


def test_cloud_from_asset_aws_legacy_account_field():
    asset = {
        "id": "abc",
        "aws_account_id": "123456789012",
        "aws_region": "eu-west-1",
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "aws"
    assert ctx.subscription_id == "123456789012"
    assert ctx.region          == "eu-west-1"


def test_cloud_from_asset_aws_v2_nested():
    asset = {
        "id": "abc",
        "cloud": {
            "aws": {
                "owner_id": "831474103278",
                "region": "us-east-1",
                "ec2_instance_id": "i-15a52aebc53722bf2",
                "ec2_instance_type": "t2.micro",
                "vpc_id": "vpc-14061aa26ba9616a7",
            }
        },
        "network": {"network_name": "Default"},
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "aws"
    assert ctx.subscription_id == "831474103278"
    assert ctx.region          == "us-east-1"
    assert ctx.resource_id     == "i-15a52aebc53722bf2"
    assert ctx.resource_type   == "t2.micro"
    assert ctx.vpc_id          == "vpc-14061aa26ba9616a7"
    assert ctx.network_name    == "Default"


def test_cloud_from_asset_azure():
    asset = {
        "id": "def",
        "azure_subscription_id": "aaaa-bbbb-cccc",
        "azure_location": "eastus",
        "azure_resource_group": "my-rg",
        "azure_resource_id": "/subscriptions/aaaa/resourceGroups/my-rg/providers/vm",
        "azure_vm_size": "Standard_D2s_v3",
        "azure_virtual_network": "my-vnet",
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "azure"
    assert ctx.subscription_id == "aaaa-bbbb-cccc"
    assert ctx.region          == "eastus"
    assert ctx.resource_group  == "my-rg"
    assert ctx.resource_type   == "Standard_D2s_v3"
    assert ctx.vpc_id          == "my-vnet"


def test_cloud_from_asset_azure_from_resource_id():
    asset = {
        "id": "def",
        "azure_resource_id": "/subscriptions/aaaa-bbbb-cccc/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm1",
        "azure_location": "eastus",
        "azure_vm_size": "Standard_D2s_v3",
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "azure"
    assert ctx.subscription_id == "aaaa-bbbb-cccc"
    assert ctx.region          == "eastus"
    assert ctx.resource_group  == "my-rg"
    assert ctx.resource_id     == "/subscriptions/aaaa-bbbb-cccc/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm1"


def test_cloud_from_asset_azure_from_cloud_common():
    asset = {
        "id": "def",
        "cloud": {
            "common": {
                "provider": "Azure",
                "subscription_id": "sub-common",
                "location": "westeurope",
                "resource_group": "shared-rg",
            }
        },
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "azure"
    assert ctx.subscription_id == "sub-common"
    assert ctx.region          == "westeurope"
    assert ctx.resource_group  == "shared-rg"


def test_cloud_from_asset_gcp_v2_nested():
    asset = {
        "id": "ghi",
        "cloud": {
            "gcp": {
                "project_id": "my-project",
                "zone": "us-central1-a",
                "instance_id": "1234567890",
                "machine_type": "n2-standard-4",
                "network": "default",
            }
        },
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "gcp"
    assert ctx.subscription_id == "my-project"
    assert ctx.region          == "us-central1-a"
    assert ctx.resource_id     == "1234567890"
    assert ctx.resource_type   == "n2-standard-4"
    assert ctx.vpc_id          == "default"
    assert ctx.resource_group  == UNKNOWN


def test_cloud_from_asset_gcp():
    asset = {
        "id": "ghi",
        "gcp_project_id": "my-project",
        "gcp_zone": "us-central1-a",
        "gcp_instance_id": "1234567890",
        "gcp_machine_type": "n2-standard-4",
        "gcp_network": "default",
    }
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "gcp"
    assert ctx.subscription_id == "my-project"
    assert ctx.region          == "us-central1-a"
    assert ctx.resource_id     == "1234567890"
    assert ctx.resource_type   == "n2-standard-4"
    assert ctx.vpc_id          == "default"
    assert ctx.resource_group  == UNKNOWN


def test_cloud_from_asset_unknown():
    asset = {"id": "xyz", "sources": [{"name": "NESSUS"}]}
    ctx = cloud_from_asset(asset)
    assert ctx.provider        == "nessus"
    assert ctx.subscription_id == UNKNOWN
    assert ctx.region          == UNKNOWN


def test_cloud_from_asset_empty():
    ctx = cloud_from_asset({})
    assert ctx.provider        == UNKNOWN
    assert ctx.subscription_id == UNKNOWN


# ── _asset_uid / _vpr_score_from_vuln ─────────────────────────────────────────

def test_asset_uid_from_asset():
    assert _asset_uid({"id": "abc-123"}) == "abc-123"


def test_asset_uid_from_vuln():
    assert _asset_uid({"asset": {"uuid": "abc-123"}}) == "abc-123"


def test_asset_uid_prefers_asset_uuid_over_finding_id():
    assert _asset_uid({"id": "finding-1", "asset": {"uuid": "asset-1"}}) == "asset-1"


def test_asset_uid_from_compliance_asset_id():
    assert _asset_uid({"asset": {"id": "asset-1"}}) == "asset-1"


@pytest.mark.parametrize("vuln,expected", [
    ({"severity": "LOW"}, "low"),
    ({"severity_id": 1}, "low"),
    ({"severity_default_id": 4}, "critical"),
    ({"severity": "3"}, "high"),
])
def test_normalize_severity(vuln, expected):
    assert _normalize_severity(vuln) == expected


def test_compliance_result_prefers_status():
    assert _compliance_result({"status": "failed"}) == "FAILED"


def test_compliance_audit_name_uses_benchmark_fallback():
    finding = {"compliance_benchmark_name": "CIS Microsoft Azure Foundations"}
    assert _compliance_audit_name(finding) == "cis microsoft azure foundations"


def test_parse_plugin_set_value_yyyymmddhhmm():
    assert _parse_plugin_set_value("202604101430") > 0


def test_parse_plugin_set_value_unix_seconds():
    assert _parse_plugin_set_value(1_551_160_800) == 1_551_160_800.0


def test_vpr_score_from_vuln_primary_path():
    vuln = {"plugin": {"vpr": {"score": 8.5}}}
    assert _vpr_score_from_vuln(vuln) == 8.5


def test_vpr_score_from_vuln_v2_fallback():
    vuln = {"plugin": {"vpr_v2": {"score": 7.2}}}
    assert _vpr_score_from_vuln(vuln) == 7.2


# ── _iter_asset_tags / _cloud_context_stats ───────────────────────────────────

def test_iter_asset_tags_includes_resource_tags():
    asset = {
        "tags": [{"key": "Owner", "value": "platform"}],
        "resource_tags": [{"key": "environment", "value": "prod"}],
    }
    assert list(_iter_asset_tags(asset)) == [
        ("owner", "platform"),
        ("environment", "prod"),
    ]


def test_cloud_context_stats_known_azure():
    ctx = AssetCloud(
        provider="azure",
        subscription_id="sub-1",
        region="eastus",
        resource_group="my-rg",
    )
    stats = _cloud_context_stats(ctx)
    assert stats[("subscription_id", "known")] == 1
    assert stats[("region", "known")] == 1
    assert stats[("resource_group", "known")] == 1


def test_cloud_context_stats_unknown_subscription():
    ctx = AssetCloud(provider="azure", subscription_id=UNKNOWN, region="eastus")
    stats = _cloud_context_stats(ctx)
    assert stats[("subscription_id", "unknown")] == 1
    assert stats[("region", "known")] == 1


def test_record_cloud_context_on_collector():
    c = _collector()
    c._reset_diagnostics()
    c._record_cloud_context("asset", AssetCloud(provider="azure", subscription_id=UNKNOWN))
    c._record_cloud_context(
        "vulnerability",
        AssetCloud(provider="azure", subscription_id=UNKNOWN, region=UNKNOWN),
    )
    assert c._cloud_context_by_entity[("asset", "azure", "subscription_id", "unknown")] == 1
    assert c._cloud_context_by_entity[("vulnerability", "azure", "region", "unknown")] == 1


def test_plugin_set_timestamp_parses_yyyymmddhhmm():
    class FakeServer:
        @staticmethod
        def properties():
            return {"loaded_plugin_set": "202604101430"}

        @staticmethod
        def status():
            return {}

    class FakeTio:
        server = FakeServer()

    ts = _plugin_set_timestamp(FakeTio())
    assert ts > 0


def test_plugin_set_timestamp_falls_back_to_status():
    class FakeServer:
        @staticmethod
        def properties():
            return {}

        @staticmethod
        def status():
            return {"plugins_expiration_date": 1_551_160_800}

    class FakeTio:
        server = FakeServer()

    assert _plugin_set_timestamp(FakeTio()) == 1_551_160_800.0


# ── TenableCollector._include ─────────────────────────────────────────────────

def _collector(providers=None, subscriptions=None):
    """Return a TenableCollector with a stub TIO (not used in these tests)."""
    return TenableCollector(
        tio=None,
        filter_providers=providers or set(),
        filter_subscriptions=subscriptions or set(),
    )


def test_include_no_filters():
    c = _collector()
    ctx = AssetCloud(provider="aws", subscription_id="123")
    assert c._include(ctx) is True


def test_include_provider_match():
    c = _collector(providers={"aws"})
    assert c._include(AssetCloud(provider="aws", subscription_id="x")) is True


def test_include_provider_no_match():
    c = _collector(providers={"azure"})
    assert c._include(AssetCloud(provider="aws", subscription_id="x")) is False


def test_include_subscription_match():
    c = _collector(subscriptions={"123"})
    assert c._include(AssetCloud(provider="aws", subscription_id="123")) is True


def test_include_subscription_no_match():
    c = _collector(subscriptions={"999"})
    assert c._include(AssetCloud(provider="aws", subscription_id="123")) is False


def test_include_both_filters_pass():
    c = _collector(providers={"aws"}, subscriptions={"123"})
    assert c._include(AssetCloud(provider="aws", subscription_id="123")) is True


def test_include_both_filters_provider_fail():
    c = _collector(providers={"azure"}, subscriptions={"123"})
    assert c._include(AssetCloud(provider="aws", subscription_id="123")) is False
