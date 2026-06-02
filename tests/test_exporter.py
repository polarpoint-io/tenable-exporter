"""Unit tests for tenable-exporter."""

import pytest
from exporter import (
    AssetCloud,
    cloud_from_asset,
    _str,
    _vpr_band,
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
        "aws_account_id": "123456789012",
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
