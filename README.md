客服后台加了脱敏，坐席点开详情页还是能看到完整身份证号：字段映射只覆盖列表页字段，详情页字段漏配；未知字段按原值返回，新增字段直接泄漏；脱敏对导出接口不生效，导出走另一条路径；角色判断用包含关系，普通角色命中管理员前缀；聚合阈值只统计行数不看分组，单组仍能反推；聚合结果不做二次脱敏，平均值泄漏个体；审计只记录查询次数，不记录字段；策略校验不检查字段覆盖率的完整性；批量处理复用规则映射，后一批次用前一批次的角色；脱敏后仍保留长度与格式，可用于校验位反推。engine/mask/view.py 是核心，tests/mask/test_view.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```bash
pytest tests -q
```

也可以用等价的 `python -m pytest tests -q`。

初始状态必须恰好输出 `15 failed`，不能出现 collection error、import error 或 syntax error，也不能有 skipped 或 passed。15 个测试都因为 `engine/mask/view.py` 中的桩函数抛出 `NotImplementedError` 而失败：

```text
15 failed in <time>
```

修复后，同一个命令应变为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 文件

```text
sec-data-mask/
├── README.md
├── conftest.py
├── engine/
│   ├── __init__.py
│   └── mask/
│       ├── __init__.py
│       └── view.py
└── tests/
    └── mask/
        └── test_view.py
```

这是 engine 嵌套布局：唯一实现文件位于 `engine/mask/view.py`，测试从 `engine.mask.view` 导入；仓库根目录的 `conftest.py` 把仓库根加入 `sys.path`，因此无需安装包即可导入嵌套模块。

## 约束

- **`tests/mask/test_view.py` 不可修改。** 只能改 `engine/mask/view.py`；15 个测试是固定契约。
- 8 个桩函数初始全部抛出 `NotImplementedError`；修复时逐个实现，只使用标准库与 pytest，离线、无随机、无第三方依赖。
- 字段级策略必须覆盖 schema 的全部字段，列表页与详情页共用同一套规则；policy 未显式配置的 schema 字段按敏感字段兜底，未知字段也绝不返回原值。
- 角色名按全等匹配且区分大小写，只有精确的 `admin` 可见原值；`admin_readonly`、`superadmin`、`Administrator` 等普通角色必须脱敏。
- 聚合先按分组统计各自行数，小于阈值时整组不输出；达到阈值后聚合值仍要二次脱敏，不能直接返回平均值。
- 导出必须复用详情页的 `mask_record` 路径；审计必须记录字段列表；策略校验必须检查字段覆盖率、聚合阈值和导出绕过；批量处理每批独立，不得复用上一批的角色或规则状态。
- 角色、阈值和格式比较的容差均为 0；脱敏输出为固定令牌 `REDACTED`，不保留原值的长度、分隔符或校验位。
