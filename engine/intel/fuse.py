"""多源威胁情报融合核心。

约定速览：
- 指标记录是 dict，键为 source、indicator、kind、verdict、confidence、timestamp。
- 策略是 dict，键为 half_life、min_confidence、conflict_rule、allowlist。
- 判定取值只有四个：malicious、allow、clean、unknown。
"""

_VALID_KINDS = ("ip", "domain", "hash")
_CONFLICT_RULE = "allowlist_then_confidence"


def normalize_indicator(value: str, kind: str) -> str:
    """把指标归一成可比较的规范形式。

    kind 为 ip 时去掉每一段的前导零（010.001.002.003 归一为 10.1.2.3）。
    kind 为 domain 时转小写并去掉全部尾点（Evil.Example.COM. 归一为 evil.example.com）。
    kind 为 hash 时转小写。
    指标为空、kind 不是 ip、domain、hash 之一、或 ip 不是四段点分十进制时抛 ValueError。
    """
    if kind not in _VALID_KINDS:
        raise ValueError(f"unknown indicator kind: {kind!r}")
    if not isinstance(value, str):
        raise ValueError("indicator must be a string")
    text = value.strip()
    if not text:
        raise ValueError("indicator is empty")

    if kind == "ip":
        parts = text.split(".")
        if len(parts) != 4 or any(not p.isdigit() for p in parts):
            raise ValueError(f"not a dotted-quad IPv4 address: {text!r}")
        return ".".join(str(int(p)) for p in parts)
    if kind == "domain":
        normalized = text.lower().rstrip(".")
        if not normalized:
            raise ValueError("indicator is empty")
        return normalized
    # hash
    return text.lower()


def decay(confidence: float, age: float, half_life: float) -> float:
    """按半衰期计算衰减后的置信度。

    age 为指标距 now 的秒数，必须大于等于零；half_life 为半衰期秒数，必须大于零。
    经过一个半衰期后置信度减半，经过两个半衰期后减到四分之一，永不归零。
    confidence 不在零到一闭区间内、age 为负、half_life 不为正数时抛 ValueError。
    """
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be within [0, 1]")
    if age < 0:
        raise ValueError("age must be non-negative")
    if half_life <= 0:
        raise ValueError("half_life must be positive")
    return confidence * 0.5 ** (age / half_life)


def dedup(records: list) -> list:
    """同源同指标去重，每个来源加指标的组合只保留最新的一条记录。

    比对的指标先归一；返回新列表与新字典，不修改入参记录。
    返回的记录里 indicator 已归一，其余字段取自被保留的那条记录。
    同一组合的时间戳相同时保留输入中靠后的一条；返回顺序按各组合首次出现的顺序。
    """
    kept = {}
    for record in records:
        normalized = normalize_indicator(record["indicator"], record["kind"])
        key = (record["source"], normalized)
        existing = kept.get(key)
        # 时间戳相同（或更新）时，输入中靠后的记录胜出。
        if existing is None or record["timestamp"] >= existing["timestamp"]:
            kept[key] = {**record, "indicator": normalized}
    return list(kept.values())


def resolve_conflict(records: list, policy: dict) -> dict:
    """对同一指标的多条记录做冲突裁决，结果与输入顺序无关。

    白名单优先：只要有一条记录的判定是 allow，最终判定就是 allow，依据为 allowlist，
    置信度取这些 allow 记录里的最大值；没有任何 allow 记录时才比较置信度，
    取置信度最高的记录（平局依次比较时间戳降序与来源升序），依据为 confidence。
    返回 indicator、verdict、confidence、sources、reason 五个键，sources 为排序后的来源列表。
    records 为空时 indicator 为 None、判定为 unknown、依据为 empty、置信度为 0.0。
    记录的指标不唯一，或 policy 的 conflict_rule 不是 allowlist_then_confidence 时抛 ValueError。
    """
    if policy.get("conflict_rule") != _CONFLICT_RULE:
        raise ValueError("unsupported conflict_rule")
    if not records:
        return {
            "indicator": None,
            "verdict": "unknown",
            "confidence": 0.0,
            "sources": [],
            "reason": "empty",
        }

    indicators = {
        normalize_indicator(r["indicator"], r["kind"]) for r in records
    }
    if len(indicators) != 1:
        raise ValueError("records refer to more than one indicator")
    indicator = indicators.pop()

    sources = sorted(r["source"] for r in records)
    allows = [r for r in records if r["verdict"] == "allow"]
    if allows:
        return {
            "indicator": indicator,
            "verdict": "allow",
            "confidence": max(r["confidence"] for r in allows),
            "sources": sources,
            "reason": "allowlist",
        }

    # 置信度降序，平局按时间戳降序、来源升序，结果与输入顺序无关。
    winner = min(
        records,
        key=lambda r: (-r["confidence"], -r["timestamp"], r["source"]),
    )
    return {
        "indicator": indicator,
        "verdict": winner["verdict"],
        "confidence": winner["confidence"],
        "sources": sources,
        "reason": "confidence",
    }


def fuse(records: list, now: float, policy: dict) -> dict:
    """把一个指标的多条记录融合成最终判定与依据。

    步骤：先归一，再按 now 与策略半衰期衰减每条记录的置信度，然后交给冲突裁决。
    白名单命中时直接判 allow，不参与置信度阈值降级；未命中且最终置信度低于
    min_confidence 时降级为 unknown，依据为 below_threshold。
    返回 indicator、verdict、confidence、allowlisted、reason、sources、evidence 七个键；
    evidence 每项含 source、kind、verdict、confidence、age、decayed，按衰减后置信度降序、来源升序排列。
    白名单命中但没有 allow 记录时置信度记为 1.0。records 为空时返回 unknown 与 empty。
    """
    if not records:
        return {
            "indicator": None,
            "verdict": "unknown",
            "confidence": 0.0,
            "allowlisted": False,
            "reason": "empty",
            "sources": [],
            "evidence": [],
        }

    half_life = policy["half_life"]
    unique = dedup(records)
    indicator = unique[0]["indicator"]

    decayed_records = []
    evidence = []
    for record in unique:
        age = max(0.0, now - record["timestamp"])
        decayed = decay(record["confidence"], age, half_life)
        decayed_records.append({**record, "confidence": decayed})
        evidence.append(
            {
                "source": record["source"],
                "kind": record["kind"],
                "verdict": record["verdict"],
                "confidence": record["confidence"],
                "age": age,
                "decayed": decayed,
            }
        )
    evidence.sort(key=lambda item: (-item["decayed"], item["source"]))

    allowlisted = check_allowlist(indicator, policy.get("allowlist") or [])
    verdict_info = resolve_conflict(decayed_records, policy)

    if allowlisted:
        verdict = "allow"
        reason = "allowlist"
        # 没有 allow 记录时，白名单命中本身给出满置信度。
        if any(r["verdict"] == "allow" for r in decayed_records):
            confidence = verdict_info["confidence"]
        else:
            confidence = 1.0
    else:
        verdict = verdict_info["verdict"]
        reason = verdict_info["reason"]
        confidence = verdict_info["confidence"]
        if confidence < policy["min_confidence"]:
            verdict = "unknown"
            reason = "below_threshold"

    return {
        "indicator": indicator,
        "verdict": verdict,
        "confidence": confidence,
        "allowlisted": allowlisted,
        "reason": reason,
        "sources": sorted(r["source"] for r in unique),
        "evidence": evidence,
    }


def _light_normalize(value: str) -> str:
    """白名单比对用的轻量归一：去空白、转小写、去尾点、IPv4 段去前导零。"""
    text = value.strip().lower().rstrip(".")
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(str(int(p)) for p in parts)
    return text


def check_allowlist(indicator: str, allowlist: list) -> bool:
    """判断指标是否精确命中白名单，不做后缀放行。

    两侧都做去空白、转小写、去尾点、IPv4 段去前导零的轻量归一后逐条全等比较。
    gateway.example.com 不会放行 a.gateway.example.com，example.com 不会放行 evil.example.com。
    不识别通配符与前缀，空名单返回 False。
    """
    if not allowlist:
        return False
    target = _light_normalize(indicator)
    return any(_light_normalize(entry) == target for entry in allowlist)


def validate_policy(policy: dict) -> list[str]:
    """返回策略问题列表，顺序固定为白名单、衰减、冲突规则。

    白名单缺失或为空列表时给出 allowlist missing；
    half_life 缺失或不为正数时给出 decay missing；
    conflict_rule 缺失或不等于 allowlist_then_confidence 时给出 conflict rule missing。
    """
    problems = []
    if not policy.get("allowlist"):
        problems.append("allowlist missing")
    half_life = policy.get("half_life")
    if (
        not isinstance(half_life, (int, float))
        or isinstance(half_life, bool)
        or half_life <= 0
    ):
        problems.append("decay missing")
    if policy.get("conflict_rule") != _CONFLICT_RULE:
        problems.append("conflict rule missing")
    return problems


def intel_batch(batches, policy: dict, now: float) -> dict:
    """批量融合，各批次互相独立。

    batches 是若干批记录列表；每批内部按归一后的指标分组，各自调用 fuse，
    结果以归一指标为键合并成一个 dict，同一指标出现在多批时后一批的结果覆盖前一批。
    任何一批都不得复用其它批的去重结果或指标集合。
    """
    fused = {}
    for batch in batches:
        # 每批重新分组、重新去重，不跨批共享任何中间结果。
        groups = {}
        for record in batch:
            key = normalize_indicator(record["indicator"], record["kind"])
            groups.setdefault(key, []).append(record)
        for indicator, group_records in groups.items():
            fused[indicator] = fuse(group_records, now, policy)
    return fused
