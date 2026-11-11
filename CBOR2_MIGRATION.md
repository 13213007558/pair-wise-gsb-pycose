# cbor2 5.x → 6.x 迁移记录

## 目标与结论

将 pycose 的 cbor2 依赖升级到 6 系列，同时保留对 5.x 的支持。迁移后：

- 全部 1653 个既有测试在 cbor2 5.9.0 与 6.2.1 下均通过（1634 原有 + 19 新增迁移向量）。
- 19 条固定消息向量在两个版本下结果一致（见下文矩阵）。
- 旧消息（含非规范编码的受保护 header）仍可验证；新解码路径可用。

## 依赖版本范围

`requirements.txt`：`cbor2>=5.0,<7.0`

兼容选择：

- 不强制 6.x：cbor2 6 需要 Python >= 3.10，而 pycose 声明支持 Python >= 3.7。
  放宽到 `>=5.0,<7.0` 让旧 Python 解析到 5.x，新 Python 解析到 6.x，同一份代码两者都可运行。
- 版本适配用**特性检测**而非版本号比较（`pycose/utils.py` 中
  `_cbor2_supports_mutable_decode()`），避免对 6.x 各小版本行为差异的脆弱假设。

## cbor2 6 的行为差异（实测，6.2.1）

1. cbor2 6.0/6.1 默认把 array/map 解码为不可变容器（tuple/frozendict）；
   6.2 起顶层默认值回到可变（`immutable=False`），但 **CBOR tag 的 value 始终解码为
   不可变容器**（为了让 `CBORTag` 可哈希）。pycose 的 `CoseMessage.decode()` 依赖
   `tag.value` 是 list（后续 `pop()` 消费），因此 6.x 全系列都需要适配。
2. `loads()`/`CBORDecoder.decode()` 新增 `immutable` 关键字（6.1+；6.0 没有该参数）。
3. 异常层级不变：`CBORDecodeError`/`CBORDecodeEOF` 均非 `ValueError` 子类，
   `CoseMessage.decode()` 的异常映射无需调整。
4. 编码侧（`dumps`、`default` 钩子签名、`CBORTag` 构造）与 5.x 兼容，无需改动。

## 代码改动

- `pycose/utils.py`：新增 `cbor_loads()`。支持 `immutable` 参数时用
  `immutable=False` 解码；随后用 `_to_mutable_containers()` 递归把残留的
  tuple/frozendict（主要是 tag value）转成 list/dict，并重建 `CBORTag`。
  map 的 key 不转换（避免把可哈希的 tuple key 变成不可哈希的 list）。
- 全部解码入口改走 `cbor_loads()`：`cosemessage.py`（消息主入口）、
  `cosebase.py`（受保护 header）、`recipient.py`（recipient 受保护 header）、
  `keys/cosekey.py`（COSE key）、`extensions/x509.py`（证书）。
- `recipient.py` 嵌套 recipient 修复（既有 bug，本次一并修复）：
  `KeyWrap.from_cose_obj`/`KeyAgreementWithKeyWrap.from_cose_obj` 原来遍历的是
  初始化后的空列表，CBOR 中第 4 个元素（嵌套 recipient 数组）被静默丢弃；
  现改为从剩余的 `cose_obj` 中解析。`DirectEncryption`/`DirectKeyAgreement`
  对多余结构改为抛 `CoseMalformedMessage`（原来静默忽略）。
- 受保护 header 的原始编码：`CoseBase` 一直保存解码时的 `phdr_encoded` 原始字节，
  签名/验签结构直接使用它，不做规范化重编码。本次未改变该设计，并用固定向量
  （非最小长度编码的 map）锁定这一行为。
- 测试：`tests/conftest.py` 与消息测试中的 `cbor2.loads` 改为 `utils.cbor_loads`
  （测试里有对解码结果的原位修改，如 RSA-OAEP 概率性密文的置空比较）。

## 固定消息向量

`tests/vectors/migration/migration-vectors.json`（19 条，确定性生成，
由 `gen_migration_vectors.py` 可复现；`tests/test_cbor2_migration.py` 驱动）：

- 正向：Sign1（ES256/EdDSA、空 protected、未知 header 属性、非规范 phdr 编码）、
  Sign（双签名者）、Encrypt0、Encrypt（direct / A128KW / 嵌套 recipient）、
  Mac0、Mac（direct）、COSE key 编解码往返。
- 负向：无 tag、未知 tag、tag 内容非数组、phdr 非 bstr、uhdr 非 map、
  截断消息、direct recipient 携带嵌套结构。
- 宽容：空 recipients 数组（见下）。

## 升级前后向量结果

| 环境 | 通过 | 说明 |
|---|---|---|
| 原始代码 + cbor2 5.9.0 | 17/19 | 嵌套 recipient 未解析；direct+嵌套被静默接受 |
| 原始代码 + cbor2 6.2.1 | 6/19 | tag value 为 tuple，所有带 tag 消息 decode 失败 |
| 迁移代码 + cbor2 5.9.0 | 19/19 | 行为与升级前一致（回归基线 1634 全过） |
| 迁移代码 + cbor2 6.2.1 | 19/19 | 新解码路径可用 |

## 特殊行为记录（非失败，但需知晓）

- `enc_empty_recipients`：空 recipients 数组在两个版本下都被宽容接受
  （`EncMessage.from_cose_obj` 的 `try/except` 兜底）。这是既有行为，按
  “保留现有支持版本的行为”原则未加严。
- `neg_direct_with_nested`：迁移前被静默接受（嵌套部分被丢弃），迁移后抛
  `CoseMalformedMessage`。这是对畸形结构的刻意加严，不影响任何合法消息。
- `enc_nested_recipient`：迁移前嵌套 recipient 在解码时被静默丢弃（上游既有
  bug），迁移后正确解析；这是本次向量集中唯一“升级前失败、升级后通过”的正向向量。

## 复现

```sh
.venv/bin/python -m pytest tests/ -q                      # 全量（含迁移向量）
.venv/bin/python -m pytest tests/test_cbor2_migration.py  # 仅迁移向量
.venv/bin/python tests/vectors/migration/gen_migration_vectors.py  # 重新生成向量（应字节一致）
```
