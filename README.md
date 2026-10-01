# 跨境药研尽调资料室

控制创新药跨境尽调材料的分级访问、分阶段开放、脱敏谱系、唯一水印、
受控问答与到期/撤权即时阻断，并让交易管理员能准确复原某一竞标方
看过的资料集合，且在结构上看不到其他交易的任何信息。

`contracts/diligence_document.json` 保存领域分类法与公开样例：材料分类
（临床数据/专利分析/生产工艺/监管往来）、敏感级别（公开/一般/机密/高敏/
患者级）、开放阶段、角色敏感级别矩阵、患者级仅脱敏规则、水印与谱系策略。
样例不含真实个人资料、业务凭据或生产连接信息。

## 运行

```bash
python3 service.py --check                         # 服务身份 + 分类法一致性检查
python3 -m unittest discover -s tests -v           # 27 项契约/领域/HTTP 测试
DATAROOM_DB=data/d.db DATAROOM_BLOB=data/blobs \
  python3 service.py --port 8000                   # 启动服务，GET /health 返回项目标识
```

仅用 Python 标准库（`http.server` + `sqlite3`），`requirements.txt` 里的
pytest 仅为可选测试运行器。

## 领域模型与关键保证

- **交易隔离的授权**：会话令牌绑定单一 `deal_id`；授权按
  交易/组织/团队/角色设置 `valid_from`~`valid_until` 期限。每次请求都
  重新计算授权（不缓存结论），因此下列事件在下一次请求立即阻断新查看：
  NDA 未签署、人员离职（跨所有交易）、撤权、授权到期、交易终止、
  组织安全冻结、交易内异常停权——错误码分别为 `nda_unsigned`、
  `user_deactivated`、`no_valid_grant`/`session_revoked`、
  `deal_terminated`、`org_frozen`、`user_suspended_in_deal`。
  访问别的交易路径一律 `cross_deal_denied`。
- **分阶段开放 + 最小权限**：文档有 `min_phase` 与敏感级别；交易阶段未到
  或角色敏感级别不足即 `phase_not_open`/`sensitivity_denied`。
- **患者级材料**：患者级原件对竞标方不可见，只能访问其脱敏子文档
  （`redaction_parent_doc_id` + 版本 `parent_version_id` 谱系）；
  不能借谱系取原件（`patient_original_blocked`/`original_admin_only`）；
  原件仅交易负责人/管理员可调取，且同样打水印上链。
- **内容指纹与管线**：每个版本入库即算 SHA-256；病毒扫描失败的版本
  连同哈希与威胁名持久化进隔离区（样本落 `blobs/quarantine/`，
  文档置 `quarantined`，任何预览/导出被拒）；上传新版本带
  `X-Expected-Version`，并发/陈旧提交得到 `409 concurrent_version`
  且冲突尝试本身上链。
- **唯一水印**：每次预览/导出都配发全局唯一 `WM-…`，同时嵌入产物
  （可机器提取，产物指纹因此唯一）、写入 `watermarks` 表与哈希链，
  记录谁在何时对哪份文档的哪个脱敏版本做了操作。
- **可续传导出**：导出建立下载会话，支持 HTTP `Range`（206）；中断
  持久化为 `interrupted` 可续传；**每个分块投放前都以该用户此刻身份
  重算授权**，撤权/离职/终止会让进行中的下载立即失败并持久化为
  `revoked`（含会话门就被拦下的情况）。
- **受控问答**：提问与答案的每条引用都必须是「提问方此刻有权查看」的
  具体文档版本——答复时校验一次，发布前再校验一次，期间撤权/离职/
  阶段变化会拒绝发布；答案须法务、医学两名不同人员分别批准
  （`dual_approval_*`）才能发布；竞标方只能读到本组织已发布问答。
- **异常与泄露处置**：滑动窗口内接触不同文档数超阈值即自动
  交易内停权 + 吊销会话 + 立安全事件（`bulk_access_anomaly`，
  默认 60 秒/8 份，可用环境变量调）；泄露事件凭外泄物中的水印标识
  溯源到人/组织/文档版本，并持久化冻结/停权/吊销等补救动作，
  事件走 `open → remediated → closed`。
- **可复原、可校验**：`GET /api/deals/{d}/forensics/viewed?org_id=…`
  准确复原某竞标方看过的资料集合（文档/版本号/版本指纹/脱敏标记/
  每次水印与时间/下载完成情况）。所有访问事实进入**按交易独立的
  哈希链** `access_event`（创世哈希含 deal_id），任何事后改写都会被
  `GET /api/deals/{d}/audit/verify` 在首处断裂序号检出。

## HTTP 接口（均在 `/api/deals/{deal_id}` 下，除引导外需 Bearer 令牌）

平台引导类接口（建交易/用户/组织/团队/签发会话令牌）设计上位于
平台网关之后，由平台侧身份保护；开通类管理接口（授权/撤权/阶段/
终止/冻结/文档上传）接受交易管理员令牌，或部署时通过
`DATAROOM_BOOTSTRAP_TOKEN` 注入的平台引导令牌（仅用于初始化开通，
不对应任何真实用户）。进入交易后的所有数据操作都受交易作用域令牌与
实时策略约束：

```
POST   /api/deals                                 建交易
POST   /api/users                                 建用户
POST   /api/users/{uid}/deactivate                离职（跨交易即时阻断）
POST   /api/deals/{d}/orgs            (nda_signed) 建竞标方组织
POST   /api/deals/{d}/orgs/{oid}/nda             补签 NDA
POST   /api/deals/{d}/teams                       建团队
POST   /api/deals/{d}/sessions                    签发交易作用域令牌
POST   /api/deals/{d}/grants                      授权（管理员，含期限/角色/组织/团队）
DELETE /api/deals/{d}/grants                      撤权（即时）
POST   /api/deals/{d}/phase                       推进开放阶段
POST   /api/deals/{d}/terminate                   终止交易
POST   /api/deals/{d}/orgs/freeze                 冻结组织
POST   /api/deals/{d}/documents                   登记文档元数据
POST   /api/deals/{d}/documents/{id}/versions     上传版本(X-Expected-Version/X-Redacted/X-Parent-Version)
GET    /api/deals/{d}/documents                   列出当前身份可见的最新版本
POST   /api/deals/{d}/versions/{vid}/preview      唯一水印预览
POST   /api/deals/{d}/versions/{vid}/export       建立可续传导出
GET    /api/deals/{d}/downloads/{dlid}            取字节(Range，逐分块实时鉴权)
POST   /api/deals/{d}/downloads/{dlid}/interrupt  标记中断
POST   /api/deals/{d}/qa                          竞标方提问（引用须自可见）
GET    /api/deals/{d}/qa                          列表（内部全量/竞标方仅本组织已发布）
POST   /api/deals/{d}/qa/{id}/answer              内部答复（引用按提问方权限校验）
POST   /api/deals/{d}/qa/{id}/legal-approve       法务批准
POST   /api/deals/{d}/qa/{id}/medical-approve     医学批准（须与法务不同人）
POST   /api/deals/{d}/qa/{id}/reject              审核驳回
POST   /api/deals/{d}/qa/{id}/publish             双审齐备 + 发布前再次校验引用
GET    /api/deals/{d}/incidents                   安全事件列表（管理员）
POST   /api/deals/{d}/incidents/leak              凭水印报泄露并自动处置
GET    /api/deals/{d}/watermarks/{wmid}           水印溯源（管理员）
GET    /api/deals/{d}/forensics/viewed?org_id=…   复原竞标方观看集合（管理员）
GET    /api/deals/{d}/audit/verify                校验本交易哈希链（管理员）
```

## 代码结构

```
dataroom/taxonomy.py      分类/级别/阶段/角色矩阵（与契约 JSON 对应）
dataroom/store.py         SQLite schema、内容寻址 blob、每交易哈希链
dataroom/policy.py        逐请求实时鉴权与患者级/阶段/角色判定
dataroom/provisioning.py  交易/组织/团队/用户/授权/会话生命周期与即时撤权
dataroom/documents.py     指纹、病毒扫描隔离、乐观并发版本、脱敏谱系
dataroom/access.py        唯一水印预览/导出、断点续传、逐分块实时鉴权
dataroom/qa.py            引用鉴权问答与法务/医学双审
dataroom/security.py      异常批量检测、水印溯源与泄露事件处置
dataroom/forensics.py     观看集合复原、跨交易隔离、链校验
service.py                HTTP 边界（保留 /health 与 --check）
tests/                    契约、20 项领域测试、5 项真实端口 HTTP 测试
```
