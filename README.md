接了三家情报源之后，同一个地址被标成高危也被标成白名单，最后谁都没拦住：地址归一不去前导零，同一地址的两种写法不合并；域名归一不去尾点，根区域名重复；哈希归一不转小写，大小写不同被当作不同指标；衰减用线性递减而不是半衰期，长期情报被过快丢弃；去重按指标而不按来源加指标，多源记录被合并成一条；冲突裁决取第一条记录，结果依赖输入顺序；白名单用后缀匹配，子域被误放行；白名单参与评分但不优先，仍可能被判高危；策略校验不检查冲突规则是否存在；批量融合复用去重结果，第二批沿用第一批的指标集合。engine/intel/fuse.py 是核心，tests/intel/test_fuse.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态是可直接运行的失败环境：`engine/intel/fuse.py` 中 8 个公开函数都是抛出 `NotImplementedError` 的桩，因此结果应恰好为 `15 failed`，而且 15 条失败全部是 `NotImplementedError`；不允许出现 collection error、import error 或 syntax error。修复完成后同一个命令应输出 `15 passed`。

测试离线、确定性：不联网、不使用随机数、不读系统时钟，`now` 一律由参数传入，只用 Python 标准库与 pytest。

## 硬性约束

- `engine/intel/fuse.py` 是唯一实现文件，当前恰好 8 个公开函数，函数体统一为 `raise NotImplementedError`。
- `tests/intel/test_fuse.py` 是验收基准，不可修改；不要删除测试、跳过测试、放宽断言或改期望值来凑绿。
- 不要改包名、目录层级与导入路径，只实现 `engine/intel/fuse.py`。
- `engine/__init__.py` 与 `engine/intel/__init__.py` 只放包声明，不要往里挪实现。
- 不引入第三方依赖，不写磁盘、不联网、不读环境变量。

## 目录布局（engine 嵌套布局）

```text
sec-threat-intel/
├── README.md
├── conftest.py
├── engine/
│   ├── __init__.py
│   └── intel/
│       ├── __init__.py
│       └── fuse.py
└── tests/
    └── intel/
        └── test_fuse.py
```

实现放在 `engine/intel/` 这一层嵌套包里，导入路径是 `engine.intel.fuse`，测试里就是 `from engine.intel.fuse import ...`。根目录的 `conftest.py` 只负责把仓库根加入 `sys.path`，不要在 `engine/` 或 `tests/` 里另加路径处理。不要改成扁平布局，也不要移动 `fuse.py`，否则导入会直接失败而不是断言失败。

## 数据约定

`records` 是由记录 dict 组成的列表，每条记录有六个键：

| 键 | 取值 |
| --- | --- |
| source | 情报源标识，字符串，如 src-a |
| indicator | 原始指标字符串，可能是未归一的地址、域名或哈希 |
| kind | ip、domain、hash 之一 |
| verdict | malicious、allow、clean、unknown 之一；allow 表示该来源把它标成白名单 |
| confidence | 零到一之间的浮点数 |
| timestamp | 该记录的产生时间，Unix 秒 |

`policy` 是策略 dict：

| 键 | 取值 |
| --- | --- |
| half_life | 半衰期秒数，正数 |
| min_confidence | 判定阈值，低于它降级为 unknown |
| conflict_rule | 目前只支持 allowlist_then_confidence |
| allowlist | 非空的精确匹配名单，元素是字符串 |

判定只允许四个值：`malicious`、`allow`、`clean`、`unknown`。依据 `reason` 只允许四个值：`allowlist`、`confidence`、`below_threshold`、`empty`。

## 缺陷清单（按修复顺序）

1. 地址归一不去前导零，同一地址两种写法不合并。
2. 域名归一不去尾点，根区域名重复。
3. 哈希归一不转小写，大小写不同被当作不同指标。
4. 衰减用线性递减而不是半衰期，长期情报被过快丢弃。
5. 去重按指标而不按来源加指标，多源记录被合并成一条。
6. 冲突裁决取第一条记录，结果依赖输入顺序。
7. 白名单用后缀匹配，子域被误放行。
8. 白名单参与评分但不优先，仍可能被判高危。
9. 策略校验不检查冲突规则是否存在。
10. 批量融合复用去重结果，第二批沿用第一批的指标集合。

## 接口约定

- `normalize_indicator(value, kind) -> str`：ip 去掉每段前导零，四段点分十进制之外抛 `ValueError`；domain 转小写并去掉全部尾点；hash 转小写；空指标与未知 `kind` 抛 `ValueError`。
- `decay(confidence, age, half_life) -> float`：指数半衰期，等于 `confidence * 0.5 ** (age / half_life)`；一个半衰期减半，三个半衰期仍有八分之一。`half_life` 非正数、`age` 为负、`confidence` 越界抛 `ValueError`。
- `dedup(records) -> list`：去重键是来源加归一后的指标，每个组合保留 `timestamp` 最大的一条，时间戳相同保留输入中靠后的一条；返回新列表与新字典，不改写入参；顺序按组合首次出现的顺序。
- `resolve_conflict(records, policy) -> dict`：白名单优先，只要存在 `verdict` 为 `allow` 的记录就判 `allow`，依据 `allowlist`，置信度取这些记录的最大值；否则取置信度最高的一条，依据 `confidence`，平局按时间戳降序、来源升序决定，结果与输入顺序无关。返回 `indicator`、`verdict`、`confidence`、`sources`、`reason`，`sources` 升序去重。空输入返回 `unknown` 与 `empty`。
- `fuse(records, now, policy) -> dict`：先归一、再按 `now - timestamp` 衰减、然后裁决；白名单命中判 `allow` 且不参与阈值降级，命中白名单但没有 `allow` 记录时置信度记为 `1.0`；未命中且置信度低于 `min_confidence` 时降级为 `unknown`，依据 `below_threshold`。返回 `indicator`、`verdict`、`confidence`、`allowlisted`、`reason`、`sources`、`evidence`；`evidence` 每项含 `source`、`kind`、`verdict`、`confidence`、`age`、`decayed`，按 `decayed` 降序、来源升序排列。
- `check_allowlist(indicator, allowlist) -> bool`：两侧都做去空白、转小写、去尾点、IPv4 段去前导零的轻量归一后逐条全等比较，只做精确匹配，不识别通配符、前缀与后缀，空名单返回 `False`。
- `validate_policy(policy) -> list[str]`：问题字符串固定为 `allowlist missing`、`decay missing`、`conflict rule missing`，顺序固定为白名单、衰减、冲突规则；完整策略返回空列表。
- `intel_batch(batches, policy, now) -> dict`：每批内部按归一指标分组后各自调用 `fuse`，结果以归一指标为键合并；任何一批都不得复用其它批的去重结果或指标集合，同一指标出现在多批时后一批覆盖前一批。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |