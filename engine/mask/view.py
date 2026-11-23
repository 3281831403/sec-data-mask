"""数据脱敏视图接口。

本模块是题目的唯一实现文件。实现时必须遵守以下总契约：

字段级策略
    每个 schema 字段都有一条独立规则，规则含 kind、sensitive、scope、
    group_by、aggregate、as 与 min_group_size。列表页字段和详情页字段
    都必须覆盖；policy 未显式配置的 schema 字段使用安全默认规则，不能
    因为漏配而返回原值。

角色
    角色名按全等匹配且区分大小写。只有精确等于 admin 的角色可以看到原值；
    admin_readonly、superadmin、Administrator 等普通角色一律脱敏。禁止用
    startswith、in 或大小写折叠判断角色。

容差 0
    角色匹配零容差；分组阈值按原始行数比较，等于阈值才出数，小于阈值整组
    不输出；脱敏结果一律为固定令牌 REDACTED，不保留原值的长度、分隔符、
    数字位或校验位，使校验位反推不可行。

其他
    只使用标准库，输入不得被原地修改，输出顺序确定，不使用随机数。
"""

# 缺陷 10：固定令牌，不保留原值长度、分隔符、数字位或校验位。
REDACTED = "REDACTED"

_ADMIN_ROLE = "admin"
_RULE_KEYS = (
    "kind",
    "sensitive",
    "scope",
    "group_by",
    "aggregate",
    "as",
    "min_group_size",
)
_SCHEMA_RULE_KEYS = ("kind", "sensitive", "scope")


def field_rules(schema, policy):
    """把 schema 与 policy 合并成字段到脱敏规则的映射。

    参数：
        schema: list[dict]，每项至少含 name 与 kind，可选 scope（list 或
            detail）与 sensitive。列表顺序即输出顺序。
        policy: dict，可含以下键：
            fields: dict，字段名到局部规则（kind、sensitive、scope、
                group_by、aggregate、as、min_group_size）的覆盖。
            default: dict，schema 字段的缺省规则，默认 kind 为 text、
                sensitive 为 True。
            aggregate: dict，可含 min_group_size，默认 5。

    返回：
        dict[str, dict]，按 schema 顺序恰好覆盖全部字段，包括只出现在
        详情页的字段。每个规则含：
            kind: str
            sensitive: bool，默认 True
            scope: str，默认 detail
            group_by: bool，默认 False
            aggregate: str 或 None，目前支持 avg
            as: str 或 None，聚合输出名；aggregate 非空时默认 字段名_avg
            min_group_size: int，来自 policy.aggregate，默认 5

    契约：
        列表页与详情页字段使用同一套合并逻辑；policy 未显式配置的 schema
        字段必须得到 sensitive 为 True 的安全默认规则，不能从结果中消失。
        合并优先级为内置默认值、policy.default、schema 字段描述、
        policy.fields 字段配置。不得修改 schema 或 policy；schema 为空时
        返回空 dict。
    """
    # 缺陷 1/2：规则映射从完整 schema 推导，列表页与详情页字段一视同仁，
    # 漏配字段也会得到 sensitive=True 的安全默认规则，而不是从映射中消失。
    policy = policy or {}
    policy_default = policy.get("default") or {}
    field_overrides = policy.get("fields") or {}
    aggregate_cfg = policy.get("aggregate") or {}
    default_min_group_size = aggregate_cfg.get("min_group_size", 5)

    rules = {}
    for descriptor in schema:
        name = descriptor["name"]
        # 内置默认值：默认敏感、默认详情页可见，失败方向必须是“脱敏”。
        rule = {
            "kind": "text",
            "sensitive": True,
            "scope": "detail",
            "group_by": False,
            "aggregate": None,
            "as": None,
            "min_group_size": default_min_group_size,
        }
        # 优先级第 2 层：policy.default。
        for key in _RULE_KEYS:
            if key in policy_default:
                rule[key] = policy_default[key]
        # 优先级第 3 层：schema 字段描述（kind/scope/sensitive）。
        for key in _SCHEMA_RULE_KEYS:
            if key in descriptor:
                rule[key] = descriptor[key]
        # 优先级第 4 层：policy.fields 显式字段配置。
        override = field_overrides.get(name)
        if override:
            for key in _RULE_KEYS:
                if key in override:
                    rule[key] = override[key]
        # 聚合输出名缺省为 字段名_avg。
        if rule["aggregate"] and not rule["as"]:
            rule["as"] = f"{name}_avg"
        rules[name] = rule
    return rules


def mask_value(kind, value, role):
    """按类型与角色脱敏单个值，返回字符串。

    规则：
        role 精确等于 admin 时返回原值的字符串形式，None 返回空字符串。
        其他角色一律返回固定令牌 REDACTED，与 kind、原值长度和原值格式
        无关；因此无法通过结果长度、分隔符位置或末位数字反推校验位。
        kind 用于表达字段语义，当前所有敏感类型共用固定令牌；未知 kind
        也按敏感处理，不得回退为原值。
        角色匹配零容差：admin_readonly、superadmin、Administrator 等都不
        是 admin，必须脱敏。

    参数：
        kind: 字段类型字符串，例如 id_card、phone、name、amount、text。
        value: 任意可转为字符串的值，允许 None。
        role: 调用者角色字符串。

    返回：
        str。admin 得到原值字符串，其他角色得到 REDACTED。
    """
    # 缺陷 4：全等且区分大小写，禁止 startswith/in/大小写折叠。
    if role == _ADMIN_ROLE:
        if value is None:
            return ""
        return str(value)
    # 缺陷 10：任何 kind（含未知 kind）都输出固定令牌，无长度/格式信息。
    return REDACTED


def mask_record(record, rules, role):
    """对一条记录做整条脱敏，返回新 dict。

    参数：
        record: dict，字段名到原始值。
        rules: field_rules 的返回值。
        role: 调用者角色字符串。

    规则：
        逐个字段处理，保持原键顺序，不修改入参。
        字段在 rules 中且 sensitive 为 False：保留原值，不做脱敏。
        字段在 rules 中且敏感：按规则 kind 调用 mask_value。
        字段不在 rules 中：按未知字段处理，使用 kind 为 text、sensitive
        为 True 的内置安全默认规则调用 mask_value，绝不能返回原值。
        role 精确等于 admin 时保留所有字段原值；其他角色一律脱敏敏感字段，
        包括 admin_readonly 这类包含 admin 前缀的角色。

    返回：
        dict，键集合与 record 相同，敏感字段的值为 REDACTED。
    """
    masked = {}
    for name, value in record.items():
        rule = rules.get(name)
        if rule is not None and not rule["sensitive"]:
            # 显式标记为非敏感的字段才允许原样保留。
            masked[name] = value
            continue
        # 缺陷 2：未知字段走 text 安全默认规则，绝不回退原值。
        kind = rule["kind"] if rule is not None else "text"
        masked[name] = mask_value(kind, value, role)
    return masked


def aggregate_guard(rows, rules, role):
    """对原始行做分组聚合并防止小分组反推。

    参数：
        rows: list[dict]，原始明细行。
        rules: field_rules 的返回值，用于识别分组字段与聚合指标。
        role: 调用者角色字符串。

    识别方式：
        恰好一个字段的 group_by 为 True，作为分组键；否则抛 ValueError。
        至少一个字段的 aggregate 为 avg，作为指标；否则抛 ValueError。
        分组字段或任一指标字段缺失的行直接跳过，不计入任何分组。
        阈值取这些指标规则 min_group_size 的最大值。

    规则：
        先按 group_by 字段分组，再逐组统计参与行数 n。
        n 小于阈值时整组不输出，连组名也不出现，避免通过组是否存在反推。
        n 大于等于阈值时输出 count 与聚合值；平均值只对参与行计算。
        聚合值必须再次经过脱敏：非 admin 角色用对应指标 kind 调用
        mask_value，得到 REDACTED；admin 精确匹配时返回数值平均值。
        角色判断零容差，admin_readonly 等按普通角色处理。

    返回：
        dict，组值到 {count: int, 指标输出名: 值} 的映射，只含达到阈值的组。
    """
    group_fields = [name for name, rule in rules.items() if rule["group_by"]]
    if len(group_fields) != 1:
        raise ValueError("group_by 字段必须恰好有一个")
    group_key = group_fields[0]

    metrics = [
        (name, rule)
        for name, rule in rules.items()
        if rule["aggregate"] == "avg"
    ]
    if not metrics:
        raise ValueError("至少需要一个 aggregate=avg 的指标字段")
    threshold = max(rule["min_group_size"] for _, rule in metrics)

    # 缺陷 5：阈值按“每个分组各自的行数”判断，而不是总行数。
    grouped = {}
    group_order = []
    for row in rows:
        if group_key not in row:
            continue
        if any(metric_name not in row for metric_name, _ in metrics):
            continue
        group_value = row[group_key]
        if group_value not in grouped:
            grouped[group_value] = []
            group_order.append(group_value)
        grouped[group_value].append(row)

    result = {}
    for group_value in group_order:
        members = grouped[group_value]
        count = len(members)
        if count < threshold:
            # 整组（含组名）都不输出。
            continue
        entry = {"count": count}
        for metric_name, rule in metrics:
            average = sum(row[metric_name] for row in members) / count
            if role == _ADMIN_ROLE:
                entry[rule["as"]] = average
            else:
                # 缺陷 6：聚合值二次脱敏，平均值本身也可能泄漏个体。
                entry[rule["as"]] = mask_value(rule["kind"], average, role)
        result[group_value] = entry
    return result


def export_view(rows, rules, role, format):
    """导出视图，与详情页共用同一套脱敏规则。

    参数：
        rows: list[dict]。
        rules: field_rules 的返回值。
        role: 调用者角色字符串。
        format: 导出格式，只支持 json 与 csv，其他值抛 ValueError。

    规则：
        推导路径必须与详情页一致：逐行调用 mask_record(record, rules, role)，
        不允许为导出另建映射或跳过脱敏，也不允许被策略中的导出开关改变。
        json 与 csv 只影响返回的 format 标记，不影响脱敏结果。
        admin 精确匹配时可见原值，其他角色（含 admin_readonly）不可见。

    返回：
        dict，含 format、rows（脱敏后的记录列表）与 count。
    """
    if format not in ("json", "csv"):
        raise ValueError("format 只支持 json 或 csv")
    # 缺陷 3：导出复用详情页 mask_record 路径，策略里的导出旁路开关被忽略。
    masked_rows = [mask_record(row, rules, role) for row in rows]
    return {
        "format": format,
        "rows": masked_rows,
        "count": len(masked_rows),
    }


def audit_access(user, record_id, fields):
    """记录一次记录查看行为，用于追责。

    参数：
        user: dict，至少含 id，可选 role。
        record_id: 被查看记录标识。
        fields: 本次查看的字段名可迭代对象，允许为空。

    返回：
        dict，含：
            user: user 的 id
            role: user 的 role，缺省为空字符串
            record_id: 原样
            fields: 按传入顺序保存的字段名列表，重复项保留
            field_count: len(fields)
            action: 固定为 view

    契约：
        必须记录具体字段列表，不能只记录次数；不得修改 user 或 fields；
        不访问存储，也不在此函数内做脱敏。
    """
    # 缺陷 7：审计落到具体字段列表，而不是只记一个查询计数。
    field_list = list(fields)
    return {
        "user": user["id"],
        "role": user.get("role", ""),
        "record_id": record_id,
        "fields": field_list,
        "field_count": len(field_list),
        "action": "view",
    }


def validate_policy(policy):
    """返回策略问题列表，空列表表示通过。

    检查项：
        未覆盖字段：policy 含 schema 列表，schema 中每个字段都必须在
            policy.fields 中显式配置；缺失字段逐条报告，问题文本包含字段名。
        聚合阈值过小：policy.aggregate.min_group_size 必须是整数且不小于
            3，否则报告阈值问题。
        导出绕过：policy.export.bypass_masking 为真或
            policy.export.apply_masking 为假时，报告导出绕过脱敏。
        其他：policy 不是 dict、缺 schema、fields 不是 dict、default 存在
            但 sensitive 不为 True，也各报告一条结构问题。

    契约：
        只检查策略结构，不访问数据；返回顺序确定：先 schema 覆盖问题，
        再默认规则问题，再聚合阈值问题，最后导出问题；不得修改 policy。
        问题文本包含对应字段名或关键词，便于调用方定位。
    """
    issues = []
    if not isinstance(policy, dict):
        return ["策略结构问题：policy 必须是 dict"]

    schema = policy.get("schema")
    if schema is None:
        issues.append("策略结构问题：缺少 schema 列表")
        schema = []

    fields = policy.get("fields")
    if not isinstance(fields, dict):
        issues.append("策略结构问题：fields 必须是 dict")
        fields = {}

    # 缺陷 8：检查字段覆盖率完整性，逐条报告漏配字段（含详情页字段）。
    for descriptor in schema:
        name = descriptor["name"] if isinstance(descriptor, dict) else descriptor
        if name not in fields:
            issues.append(f"字段覆盖不完整：字段 {name} 未在 policy.fields 中显式配置")

    # 默认规则必须保持敏感兜底。
    default = policy.get("default")
    if default is not None and default.get("sensitive") is not True:
        issues.append("默认规则问题：default.sensitive 必须为 True")

    # 聚合阈值：整数且不小于 3（bool 不算整数）。
    aggregate = policy.get("aggregate") or {}
    min_group_size = aggregate.get("min_group_size") if isinstance(aggregate, dict) else None
    if (
        not isinstance(min_group_size, int)
        or isinstance(min_group_size, bool)
        or min_group_size < 3
    ):
        issues.append("聚合阈值问题：aggregate.min_group_size 必须是不小于 3 的整数")

    # 导出绕过开关一律视为问题。
    export = policy.get("export") or {}
    if isinstance(export, dict):
        if export.get("bypass_masking") or export.get("apply_masking") is False:
            issues.append("导出绕过问题：导出接口禁止关闭或绕过脱敏")

    return issues


def mask_batch(batches, policy, role):
    """批量脱敏，各批次相互独立。

    参数：
        batches: list[dict]，每批含 rows（list[dict]），可选 id 与 role。
        policy: 含 schema 的完整策略。
        role: 批次未指定 role 时使用的默认角色。

    规则：
        每个批次单独调用 field_rules(policy.schema, policy)，再逐行调用
        mask_record。批次 role 优先于默认 role；不同批次不得共享角色、
        规则映射或任何可变状态，后一批次不能沿用前一批次的角色。
        缺 id 的批次按其在列表中的位置生成字符串键 0、1 等；id 重复时
        后者覆盖前者。输入 batches、policy 与其中的记录均不得被修改。

    返回：
        dict，批次键到 {role: 实际角色, rows: 脱敏后记录列表} 的映射。
    """
    result = {}
    for index, batch in enumerate(batches):
        # 缺陷 9：每批独立推导规则、独立取角色，不复用任何批次间状态。
        batch_key = str(batch["id"]) if "id" in batch else str(index)
        batch_role = batch["role"] if "role" in batch else role
        batch_rules = field_rules(policy["schema"], policy)
        result[batch_key] = {
            "role": batch_role,
            "rows": [
                mask_record(row, batch_rules, batch_role)
                for row in batch["rows"]
            ],
        }
    return result
