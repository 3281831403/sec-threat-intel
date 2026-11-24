"""sec-threat-intel 的验收测试。

测试离线、确定性：不联网、不使用随机数、不读系统时钟，now 一律由参数传入。
只使用 Python 标准库与 pytest。
"""

import pytest

from engine.intel.fuse import (
    check_allowlist,
    decay,
    dedup,
    fuse,
    intel_batch,
    normalize_indicator,
    resolve_conflict,
    validate_policy,
)

NOW = 1_700_000_000
HALF_LIFE = 86400.0


def policy(**overrides):
    base = {
        "half_life": HALF_LIFE,
        "min_confidence": 0.35,
        "conflict_rule": "allowlist_then_confidence",
        "allowlist": ["gateway.example.com", "10.1.2.3"],
    }
    base.update(overrides)
    return base


def record(
    source,
    indicator,
    kind="ip",
    verdict="malicious",
    confidence=0.9,
    timestamp=NOW,
):
    return {
        "source": source,
        "indicator": indicator,
        "kind": kind,
        "verdict": verdict,
        "confidence": confidence,
        "timestamp": timestamp,
    }


def test_ip_indicator_normalization_strips_leading_zeros():
    # Defect 1: 010.001.002.003 与 10.1.2.3 是同一个地址，必须归一后合并。
    assert normalize_indicator("010.001.002.003", "ip") == "10.1.2.3"
    assert normalize_indicator(" 10.1.2.3 ", "ip") == "10.1.2.3"
    assert normalize_indicator("000.000.000.000", "ip") == "0.0.0.0"

    records = [
        record("src-a", "010.1.2.3", confidence=0.85, timestamp=NOW - 30),
        record("src-a", "10.1.2.3", confidence=0.40, timestamp=NOW + 10),
    ]
    kept = dedup(records)
    assert len(kept) == 1
    assert kept[0]["indicator"] == "10.1.2.3"
    assert kept[0]["confidence"] == 0.40
    # dedup 不得就地改写入参记录。
    assert records[0]["indicator"] == "010.1.2.3"


def test_domain_indicator_normalization_strips_trailing_dot():
    # Defect 2: 根区域名带尾点，归一后与不带尾点是同一个域名。
    assert normalize_indicator("Evil.Example.COM.", "domain") == "evil.example.com"
    assert normalize_indicator("evil.example", "domain") == "evil.example"
    assert normalize_indicator("evil.example...", "domain") == "evil.example"

    records = [
        record("src-a", "evil.example.", kind="domain", confidence=0.9, timestamp=NOW - 10),
        record("src-a", "Evil.Example", kind="domain", confidence=0.55, timestamp=NOW + 5),
    ]
    kept = dedup(records)
    assert len(kept) == 1
    assert kept[0]["indicator"] == "evil.example"
    assert kept[0]["confidence"] == 0.55


def test_hash_indicator_normalization_lowercases():
    # Defect 3: 哈希大小写不同仍是同一个指标。
    upper = "AB" * 32
    lower = "ab" * 32
    assert normalize_indicator(upper, "hash") == lower
    assert normalize_indicator("  " + upper + "  ", "hash") == lower

    records = [
        record("src-a", upper, kind="hash", confidence=0.9, timestamp=NOW - 10),
        record("src-a", lower, kind="hash", confidence=0.6, timestamp=NOW + 10),
    ]
    kept = dedup(records)
    assert len(kept) == 1
    assert kept[0]["indicator"] == lower
    assert kept[0]["confidence"] == 0.6

    with pytest.raises(ValueError):
        normalize_indicator("10.0.0.1", "cidr")
    with pytest.raises(ValueError):
        normalize_indicator("", "ip")


def test_decay_uses_half_life_not_linear():
    # Defect 4: 衰减按半衰期指数递减，线性递减会把长期情报直接抹成零。
    assert decay(1.0, 0.0, HALF_LIFE) == pytest.approx(1.0)
    assert decay(0.8, HALF_LIFE, HALF_LIFE) == pytest.approx(0.4)
    assert decay(0.8, 2 * HALF_LIFE, HALF_LIFE) == pytest.approx(0.2)
    assert decay(0.8, 3 * HALF_LIFE, HALF_LIFE) == pytest.approx(0.1)
    # 线性递减在一个半衰期处就已经是零，指数递减必须仍然为正。
    assert decay(0.8, HALF_LIFE, HALF_LIFE) > 0.0
    assert decay(0.8, 3 * HALF_LIFE, HALF_LIFE) > 0.0

    with pytest.raises(ValueError):
        decay(0.8, 10.0, 0)
    with pytest.raises(ValueError):
        decay(0.8, -1.0, HALF_LIFE)


def test_dedup_keys_on_source_and_indicator():
    # Defect 5: 去重键是来源加指标，不能只按指标，否则多源记录被合并成一条。
    records = [
        record("src-a", "203.0.113.9", confidence=0.85, timestamp=NOW - 60),
        record("src-b", "203.0.113.9", confidence=0.40, timestamp=NOW - 30),
        record("src-a", "203.0.113.9", confidence=0.70, timestamp=NOW),
    ]
    kept = dedup(records)
    assert len(kept) == 2
    assert [item["source"] for item in kept] == ["src-a", "src-b"]

    by_source = {item["source"]: item for item in kept}
    assert by_source["src-a"]["confidence"] == 0.70
    assert by_source["src-a"]["timestamp"] == NOW
    assert by_source["src-b"]["confidence"] == 0.40
    assert by_source["src-b"]["timestamp"] == NOW - 30


def test_conflict_resolution_is_order_independent():
    # Defect 6: 裁决不能取第一条记录，换个输入顺序结果必须不变。
    high = record("src-a", "198.51.100.7", confidence=0.92, timestamp=NOW - 100)
    low = record("src-b", "198.51.100.7", confidence=0.31, timestamp=NOW - 10)
    p = policy()

    first = resolve_conflict([high, low], p)
    second = resolve_conflict([low, high], p)
    assert first == second
    assert first["indicator"] == "198.51.100.7"
    assert first["verdict"] == "malicious"
    assert first["confidence"] == pytest.approx(0.92)
    assert first["reason"] == "confidence"
    assert first["sources"] == ["src-a", "src-b"]


def test_allowlist_matching_is_exact_not_suffix():
    # Defect 7: 白名单精确匹配，子域与前缀相近的域名都不放行。
    assert check_allowlist("gateway.example.com", ["gateway.example.com"]) is True
    assert check_allowlist("Gateway.Example.COM.", ["gateway.example.com"]) is True
    assert check_allowlist("a.gateway.example.com", ["gateway.example.com"]) is False
    assert check_allowlist("notgateway.example.com", ["gateway.example.com"]) is False
    assert check_allowlist("evil.example.com", ["example.com"]) is False
    assert check_allowlist("10.1.2.3", ["010.001.002.003"]) is True
    assert check_allowlist("10.1.2.4", ["10.1.2.0"]) is False
    assert check_allowlist("gateway.example.com", []) is False


def test_resolve_conflict_prioritizes_allowlist_over_score():
    # Defect 8: 白名单优先于评分，高置信度高危不能盖住白名单证据。
    p = policy()
    records = [
        record("src-a", "203.0.113.5", confidence=0.99, timestamp=NOW),
        record("src-b", "203.0.113.5", confidence=0.88, timestamp=NOW),
        record("src-c", "203.0.113.5", verdict="allow", confidence=0.20, timestamp=NOW),
    ]
    for ordered in (records, list(reversed(records))):
        result = resolve_conflict(ordered, p)
        assert result["verdict"] == "allow"
        assert result["confidence"] == pytest.approx(0.20)
        assert result["reason"] == "allowlist"
        assert result["sources"] == ["src-a", "src-b", "src-c"]


def test_validate_policy_checks_conflict_rule():
    # Defect 9: 策略校验必须检查冲突规则是否存在，缺规则不能算通过。
    assert validate_policy(policy()) == []

    partial = policy()
    del partial["conflict_rule"]
    assert validate_policy(partial) == ["conflict rule missing"]

    bad_rule = policy(conflict_rule="first_wins")
    assert validate_policy(bad_rule) == ["conflict rule missing"]

    assert validate_policy({}) == [
        "allowlist missing",
        "decay missing",
        "conflict rule missing",
    ]
    assert validate_policy(policy(allowlist=[])) == ["allowlist missing"]
    assert validate_policy(policy(half_life=0)) == ["decay missing"]


def test_intel_batch_keeps_each_batch_independent():
    # Defect 10: 第二批不得沿用第一批的去重结果与指标集合，每批独立融合。
    p = policy()
    batch_one = [
        record("src-a", "192.0.2.10", confidence=0.90),
        record("src-b", "198.51.100.77", confidence=0.80, timestamp=NOW - 3600),
    ]
    batch_two = [
        record("src-b", "192.0.2.20", confidence=0.80),
        record("src-a", "198.51.100.77", confidence=0.60),
    ]

    result = intel_batch([batch_one, batch_two], p, NOW)
    assert set(result) == {"192.0.2.10", "192.0.2.20", "198.51.100.77"}
    assert result["192.0.2.10"]["sources"] == ["src-a"]
    assert result["192.0.2.20"]["sources"] == ["src-b"]
    assert result["192.0.2.10"]["verdict"] == "malicious"
    assert result["192.0.2.20"]["verdict"] == "malicious"

    # 198.51.100.77 在两批里都出现，第二批只能看到自己的那条记录：
    # 若沿用第一批的去重结果，来源会多出 src-b，证据也会变成两条。
    shared = result["198.51.100.77"]
    assert shared["sources"] == ["src-a"]
    assert [item["source"] for item in shared["evidence"]] == ["src-a"]
    assert len(shared["evidence"]) == 1


def test_single_high_confidence_source_is_malicious():
    # 单一高危来源在置信度足够时判高危，依据是置信度。
    p = policy()
    result = fuse([record("src-a", "198.51.100.23", confidence=0.90)], NOW, p)
    assert result["indicator"] == "198.51.100.23"
    assert result["verdict"] == "malicious"
    assert result["confidence"] == pytest.approx(0.90)
    assert result["allowlisted"] is False
    assert result["reason"] == "confidence"
    assert result["sources"] == ["src-a"]
    assert len(result["evidence"]) == 1


def test_fuse_allowlist_overrides_high_risk():
    # 白名单覆盖高危：策略白名单命中时，即使记录全是高置信度高危也只判 allow。
    p = policy(allowlist=["gateway.example.com"])
    records = [
        record(
            "src-a",
            "gateway.example.com",
            kind="domain",
            confidence=0.97,
            timestamp=NOW - 60,
        ),
        record(
            "src-b",
            "Gateway.Example.COM.",
            kind="domain",
            confidence=0.91,
            timestamp=NOW - 30,
        ),
    ]
    result = fuse(records, NOW, p)
    assert result["allowlisted"] is True
    assert result["indicator"] == "gateway.example.com"
    assert result["verdict"] == "allow"
    assert result["reason"] == "allowlist"
    assert result["confidence"] == pytest.approx(1.0)
    assert result["sources"] == ["src-a", "src-b"]


def test_decayed_confidence_falls_below_threshold():
    # 置信度随时间衰减到阈值以下：一个半衰期后仍在阈值上，四个半衰期后降级为 unknown。
    p = policy(min_confidence=0.35)
    fresh = record("src-a", "203.0.113.77", confidence=0.80, timestamp=NOW - HALF_LIFE)
    stale = record("src-a", "203.0.113.77", confidence=0.80, timestamp=NOW - 4 * HALF_LIFE)

    fresh_result = fuse([fresh], NOW, p)
    assert fresh_result["confidence"] == pytest.approx(0.40)
    assert fresh_result["verdict"] == "malicious"
    assert fresh_result["reason"] == "confidence"

    stale_result = fuse([stale], NOW, p)
    assert stale_result["confidence"] == pytest.approx(0.05)
    assert stale_result["verdict"] == "unknown"
    assert stale_result["reason"] == "below_threshold"


def test_same_source_duplicates_count_once():
    # 同源重复记录只算一条：同一来源的三条记录在证据里只剩最新那条。
    p = policy(allowlist=["gateway.example.com"])
    records = [
        record("src-a", "192.0.2.44", confidence=0.90, timestamp=NOW - 200),
        record("src-a", "192.0.2.44", confidence=0.50, timestamp=NOW - 100),
        record("src-a", "192.0.2.44", confidence=0.70, timestamp=NOW),
    ]
    result = fuse(records, NOW, p)
    assert len(result["evidence"]) == 1
    assert result["sources"] == ["src-a"]
    assert result["evidence"][0]["source"] == "src-a"
    assert result["evidence"][0]["confidence"] == pytest.approx(0.70)
    assert result["evidence"][0]["age"] == pytest.approx(0.0)
    assert result["confidence"] == pytest.approx(0.70)
    assert result["verdict"] == "malicious"


def test_intel_batch_matches_individual_fuse_calls():
    # 两批独立融合与单独融合相同：批量结果逐指标等于单独调用 fuse。
    p = policy()
    batch_one = [
        record("src-a", "198.51.100.8", confidence=0.90, timestamp=NOW - 120),
    ]
    batch_two = [
        record(
            "src-b",
            "gateway.example.com",
            kind="domain",
            confidence=0.60,
            timestamp=NOW - 3600,
        ),
    ]

    combined = intel_batch([batch_one, batch_two], p, NOW)
    expected = {
        "198.51.100.8": fuse(batch_one, NOW, p),
        "gateway.example.com": fuse(batch_two, NOW, p),
    }
    assert combined == expected
    assert combined["gateway.example.com"]["verdict"] == "allow"
    assert combined["198.51.100.8"]["verdict"] == "malicious"