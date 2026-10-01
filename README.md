# 跨境药研尽调受控资料室

为创新药跨境交易构建的受控资料室（VDR）：多家跨国药企并行尽调时，按交易、组织、
团队、角色与期限隔离访问；临床数据、专利分析、生产工艺、监管往来四类材料按
阶段门与敏感级别分阶段开放，外部只能查看脱敏版本。

`contracts/diligence_document.json` 保存领域约定（材料分类、敏感级别 L1–L4、
脱敏层级、角色、阶段门）。样例不含真实个人资料、业务凭据或生产连接信息。

## 核心能力

- **授权实时求值**：每次查看都重新校验 NDA、在职状态、授权有效性、交易状态、
  阶段门、敏感级别、角色与脱敏层级。NDA 未签/撤回、人员离职、撤权、交易终止
  对**下一次新查看立即生效**，不依赖会话过期。
- **四级主体**：交易 → 组织（竞标方/内部）→ 团队 → 用户；授权可设分类范围与
  `valid_from/valid_until` 期限。
- **内容指纹与脱敏谱系**：上传内容 SHA-256 指纹、内容寻址存储；脱敏件以
  `父版本.序号` 子版本挂载，父子双向可溯（原件 v1 → 标准脱敏 v1.1 → 聚合脱敏 v1.2）。
- **病毒扫描隔离**：文件先进隔离区，扫描失败永久隔离并立 `SCAN_FAILED` 事件，
  任何主体不可见；通过后升入清洁区。内置 EICAR 静态扫描器，可替换杀软适配器。
- **断点续传与并发控制**：分块上传、重复分块幂等；新原件版本基于乐观版本号，
  冲突件入隔离区并持久化 `VERSION_CONFLICT` 事件。
- **唯一水印**：每次预览/导出由水印密钥 HMAC 生成唯一码与可见水印
  （交易/组织/人员/时间/码），可离线验证、可凭码溯源访问记录。
- **导出管控**：L4 患者级材料逐次审批；下载中断持久化为 `DOWNLOAD_INTERRUPTED`；
  拉取每一块前都重新跑授权判定（导出途中撤权立即断流）。
- **异常与泄露处置**：滑动窗口检测异常批量访问，超阈自动停权并立案；泄露事件
  凭水印溯源到人，可一键冻结个人或整个竞标方、注销会话、撤权；每事件独立 JSON
  卷宗，处置动作仅追加。
- **受限问答双审**：提问与答案只能引用提问方**当前有权查看**的具体版本；
  法务 + 医学双审通过才可发布，发布瞬间再次复核引用可见性（审核期内被撤权则
  阻断发布，恢复后可显式重发）；竞标方之间互不可见。
- **审计复原与交易隔离**：仅追加 JSONL 审计日志，可精确复原某竞标方/某人
  曾看过的资料集合（版本、脱敏层级、动作、次数、末次时间）。管理员隶属特定
  交易，跨交易访问一律 `CROSS_DEAL` 拒绝；不存在可见全部交易的全局角色。

## 落盘布局

```
<data_dir>/state.json                 原子写入的主状态（含乐观版本号 rev）
<data_dir>/audit.jsonl                仅追加审计日志（每次访问/拒绝/处置一行）
<data_dir>/incidents/<INC-id>.json    事件卷宗（事件 + 相关审计轨迹 + 处置动作）
<data_dir>/blobs/clean/<sha256>       扫描通过的内容寻址文件
<data_dir>/blobs/quarantine/<sha256>  待扫/染毒隔离文件
<data_dir>/uploads/<upload_id>/       分块上传暂存
```

## 运行

```bash
python3 service.py --check                      # 基础身份检查
python3 service.py --data-dir ./data --port 8000  # 启动完整 JSON API
python3 -m unittest discover -s tests -v        # 全部契约与端到端测试（22 项）
```

健康检查：`GET /health`。除 `/health`、`/admin/bootstrap`、`/auth/enroll`、
`/auth/login` 外，所有接口需要 `Authorization: Bearer <会话令牌>`。

## 主要 API

| 区域 | 端点 |
| --- | --- |
| 引导/认证 | `POST /admin/bootstrap`、`/auth/enroll`、`/auth/login`、`/auth/logout` |
| 交易/组织 | `POST /orgs`、`/orgs/{id}/teams`、`POST /invitations`、`POST /deals/{id}/phase`、`/deals/{id}/terminate` |
| 人员状态 | `POST /users/{id}/nda/sign`、`/nda/withdraw`、`/users/{id}/offboard` |
| 授权 | `POST /grants`、`POST /grants/{id}/revoke` |
| 文档谱系 | `POST /documents`、`GET /documents?deal_id=`、`GET /documents/{id}/lineage`、`/withdraw` |
| 上传 | `POST /uploads`、`PUT /uploads/{id}/chunks/{n}`、`POST /uploads/{id}/complete`、`/abort` |
| 访问 | `GET /documents/{id}/versions/{v}/preview`、`POST /exports`、`/exports/{id}/approve`、`GET /exports/{id}/fetch`、`/interrupt` |
| 问答 | `POST /questions`、`POST /questions/{id}/answer`、`/questions/{id}/reviews/{legal|medical}`、`/publish` |
| 事件 | `POST /incidents/leak`、`GET /incidents`、`/incidents/{id}/actions`、`/resolve`、`GET /watermark/verify?code=` |
| 复原 | `GET /reconstruction/org`、`/reconstruction/user`、`GET /audit?deal_id=` |

被拒绝的访问同样写入审计（`result=DENIED` 与具体原因码），可证明“谁在何时因何被阻断”。

## 模块结构

- `dataroom/contract.py` — 领域契约加载与校验
- `dataroom/security.py` — 指纹、HMAC 水印、令牌、原子写入、时间源
- `dataroom/storage.py` — 原子状态、仅追加日志、内容寻址 blob、事件卷宗
- `dataroom/authz.py` — 实时授权引擎（交易/组织/团队/用户 + 阶段门）
- `dataroom/models.py` — 实体工厂与状态机常量
- `dataroom/documents.py` — 分块上传、扫描隔离、谱系、水印预览/导出、异常检测
- `dataroom/incidents.py` — 事件立案、处置、泄露水印溯源
- `dataroom/audit.py` — 审计日志、滑动窗口检测、浏览集合复原
- `dataroom/qa.py` — 受限问答与法务/医学双审
- `dataroom/app.py` — 总装门面（生命周期、应急、按交易隔离的审计复原）
- `dataroom/httpapi.py` — JSON HTTP API
