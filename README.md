# 科研样品全生命周期管理服务

这是一个面向科研机构样品库、实验室和课题组的模块化后端，集中管理样品接收、分装、借用、归还、消耗、销毁、库存盘点、谱系事件、保管位置、异常记录、登录权限、审计以及可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 已有能力

- 身份与权限：支持引导管理员、登录、会话、用户、角色和细粒度权限。
- 批次与二维码：接收批次保存项目、数量和稳定二维码载荷。
- 样品档案：登记样品、数量、单位、保管位置和生命周期状态。
- 分装谱系：一次事务内扣减母样、创建子样、记录损耗与事件链。
- 借用归还：保存借用数量、到期时间、部分归还和最终归还状态。
- 实验消耗：使用幂等键登记消耗，防止重复请求二次扣减。
- 位置脱敏：普通权限只能看到受限位置的替代码，授权人员可查看精确位置。
- 双人审批：高风险操作要求申请人与审批人分离，并累计不同审批人的决定。
- 异常追踪：异常可以关联样品或接收批次，保存严重度和处理状态。
- 调查案件：把多条异常归并为可关联的调查案件，按接收批次、保管位置、谱系祖先和时间窗口生成候选关联，人工确认后统一执行隔离或观察措施。案件保存假设、追加式证据版本、责任人、处置步骤与截止时间；严重度只能单调升级，乐观锁版本防止旧更新覆盖。结案前必须逐项解释受影响样品、完成全部处置步骤，并由另一名人员批准解除措施，隔离样品自动恢复原状态。
- 审计与任务：关键身份及业务操作留痕，后台任务支持去重、领取与完成；逾期巡检与关联扫描任务使用自然唯一键和幂等日志，重复执行安全。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/samples.db`，可用 `SAMPLE_DATABASE_PATH` 指定其他路径。

## 初始化与完整性检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动 API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 测试

```bash
python -m pytest
```

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

## 调查案件流程

1. 登记异常后创建案件（`POST /api/investigations`，可直接携带 `anomaly_ids`），填写假设、严重度、责任人和截止时间。
2. 用 `POST /api/investigations/associations/preview` 按批次/位置/谱系/时间窗口预览候选（返回每条候选的关联依据 `basis`），确认后用 `.../associations/import` 导入为候选；也可经 `.../associations/scan-jobs` 投递后台扫描任务，重复扫描只做 upsert，不产生重复候选。
3. 通过 `affected/confirm` 人工确认受影响样品并指定措施（`quarantine` 隔离或 `observe` 观察），`measures/apply` 统一执行；隔离会记录样品原状态，重放请求返回 `replayed`。
4. 追加证据（`evidence`，支持 `idempotency_key`，版本号单调递增）与处置步骤（`actions`，`step_code` 幂等）。
5. 全部样品逐项 `explain`、步骤全部完成后才能 `closure/request`；解除措施必须由责任人、申请人和创建人之外的另一名具备 `investigations.approve_release` 权限的人员 `closure/decision` 批准，批准后自动解除隔离并恢复样品状态。
6. `GET /api/investigations` 支持 `overdue`、`state`、`owner_user_id` 过滤，列表与详情稳定展示关联依据、逾期标记和未完成动作数量。
