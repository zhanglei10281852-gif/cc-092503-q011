from __future__ import annotations


def _make_batch_samples(client, admin, *, code_prefix="INV", location_sensitivity="normal"):
    location = client.post(
        "/api/samples/locations",
        headers=admin["headers"],
        json={
            "code": f"{code_prefix}-LOC",
            "building": "样品楼",
            "room": "常温库",
            "cabinet": "柜一",
            "shelf": "一层",
            "sensitivity": location_sensitivity,
            "capacity_units": 50,
        },
    ).json()
    batch = client.post(
        "/api/samples/batches",
        headers=admin["headers"],
        json={"batch_code": f"{code_prefix}-BATCH", "project_code": code_prefix, "expected_count": 4},
    ).json()

    def register(sample_code, location_id=None):
        return client.post(
            "/api/samples",
            headers=admin["headers"],
            json={
                "sample_code": sample_code,
                "batch_id": batch["id"],
                "sample_type": "血样",
                "quantity": 10,
                "unit": "mL",
                "location_id": location_id if location_id is not None else location["id"],
            },
        ).json()

    parent = register(f"{code_prefix}-S1")
    child_a = register(f"{code_prefix}-S2")
    aliquot = client.post(
        f"/api/samples/{parent['id']}/aliquots",
        headers=admin["headers"],
        json={
            "requested_quantity": 4,
            "loss_quantity": 0,
            "children": [{"sample_code": f"{code_prefix}-S3", "quantity": 4}],
        },
    )
    assert aliquot.status_code == 201, aliquot.text
    child_lineage = aliquot.json()["children"][0]
    return location, batch, parent, child_a, child_lineage


def _anomaly(client, admin, **overrides):
    payload = {
        "anomaly_type": "标签破损",
        "severity": "high",
        "description": "二维码标签与人工编号无法对应",
    }
    payload.update(overrides)
    response = client.post("/api/samples/anomalies", headers=admin["headers"], json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _second_approver(client, admin, username="approver2"):
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "Approver!23456",
            "display_name": "复核人乙",
            "role_codes": ["approver"],
        },
    )
    assert created.status_code == 201, created.text
    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Approver!23456", "client_label": "tests"},
    )
    assert login.status_code == 200, login.text
    body = login.json()
    return {"headers": {"Authorization": f"Bearer {body['token']}"}, "body": body, "id": body["user"]["id"]}


def test_investigation_groups_anomalies_and_affected_samples(client, admin):
    _, batch, parent, child_a, child_lineage = _make_batch_samples(client, admin)
    anomaly_parent = _anomaly(client, admin, sample_id=parent["id"], anomaly_type="温控偏离")
    anomaly_batch = _anomaly(client, admin, batch_id=batch["id"], anomaly_type="数量差异")

    created = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={
            "title": "冷链批次共同来源调查",
            "hypothesis": "运输环节温控失效导致整批标签胶失效",
            "severity": "high",
            "owner_user_id": admin["body"]["user"]["id"],
            "anomaly_ids": [anomaly_parent["id"], anomaly_batch["id"]],
        },
    )
    assert created.status_code == 201, created.text
    inv = created.json()
    assert inv["status"] == "open"
    assert {link["anomaly_id"] for link in inv["anomaly_links"]} == {anomaly_parent["id"], anomaly_batch["id"]}
    assert all(link["status"] == "confirmed" for link in inv["anomaly_links"])
    # 异常指向的样品自动进入候选受影响清单
    assert [s["sample_id"] for s in inv["affected_samples"]] == [parent["id"]]


def test_candidate_preview_explains_basis_by_batch_location_lineage_and_window(client, admin):
    location, batch, parent, child_a, child_lineage = _make_batch_samples(client, admin)
    seed = _anomaly(client, admin, sample_id=parent["id"], anomaly_type="温控偏离")
    _anomaly(client, admin, sample_id=child_a["id"], anomaly_type="标签破损")

    preview = client.post(
        "/api/investigations/associations/preview",
        headers=admin["headers"],
        json={"seed_anomaly_id": seed["id"], "window_hours": 72},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    dimension_types = {d["type"] for d in body["dimensions"]}
    assert {"batch", "location", "lineage", "time_window"} <= dimension_types

    related = [c for c in body["anomaly_candidates"] if not c.get("is_seed")]
    assert related and "batch" in {r["type"] for r in related[0]["basis"]}

    sample_candidates = {c["sample_id"]: c for c in body["sample_candidates"]}
    # 同批、同库位、同谱系祖先的样品都应被命中
    assert child_a["id"] in sample_candidates
    lineage_hit = sample_candidates[child_lineage["id"]]
    basis_types = {b["type"] for b in lineage_hit["basis"]}
    assert {"lineage", "batch"} <= basis_types


def test_import_candidates_is_safe_to_rerun(client, admin):
    _, _, parent, child_a, _ = _make_batch_samples(client, admin)
    seed = _anomaly(client, admin, sample_id=parent["id"])
    inv = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={"title": "重复扫描案件", "severity": "medium", "owner_user_id": admin["body"]["user"]["id"]},
    ).json()
    query = {"seed_anomaly_id": seed["id"], "window_hours": 72}
    first = client.post(f"/api/investigations/{inv['id']}/associations/import", headers=admin["headers"], json=query)
    assert first.status_code == 200, first.text
    assert first.json()["new_sample_candidates"] >= 1
    second = client.post(f"/api/investigations/{inv['id']}/associations/import", headers=admin["headers"], json=query)
    assert second.json()["new_anomaly_candidates"] == 0
    assert second.json()["new_sample_candidates"] == 0
    assert second.json()["replayed"] is True

    detail = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()
    sample_ids = [s["sample_id"] for s in detail["affected_samples"]]
    assert len(sample_ids) == len(set(sample_ids))
    # 候选必须稳定展示关联依据
    assert all(s["basis"] for s in detail["affected_samples"])


def test_severity_escalation_cannot_be_overwritten_by_stale_update(client, admin):
    _, _, parent, _, _ = _make_batch_samples(client, admin)
    anomaly = _anomaly(client, admin, sample_id=parent["id"])
    inv = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={
            "title": "严重度升级案件", "severity": "low",
            "owner_user_id": admin["body"]["user"]["id"],
            "anomaly_ids": [anomaly["id"]],
        },
    ).json()
    stale_version = inv["version"]
    upgraded = client.patch(
        f"/api/investigations/{inv['id']}",
        headers=admin["headers"],
        json={"severity": "critical", "expected_version": stale_version},
    )
    assert upgraded.status_code == 200
    assert upgraded.json()["severity"] == "critical"

    stale = client.patch(
        f"/api/investigations/{inv['id']}",
        headers=admin["headers"],
        json={"severity": "low", "expected_version": stale_version},
    )
    assert stale.status_code == 409

    downgrade = client.patch(
        f"/api/investigations/{inv['id']}",
        headers=admin["headers"],
        json={"severity": "medium", "expected_version": upgraded.json()["version"]},
    )
    assert downgrade.status_code == 409


def test_full_quarantine_closure_requires_explanations_actions_and_second_approver(client, admin):
    _, _, parent, child_a, _ = _make_batch_samples(client, admin)
    anomaly = _anomaly(client, admin, sample_id=parent["id"], anomaly_type="温控偏离")
    inv = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={
            "title": "隔离解除全流程", "hypothesis": "温控批次问题", "severity": "high",
            "owner_user_id": admin["body"]["user"]["id"], "anomaly_ids": [anomaly["id"]],
        },
    ).json()

    # 导入候选并确认两个样品隔离
    client.post(
        f"/api/investigations/{inv['id']}/associations/import",
        headers=admin["headers"],
        json={"seed_anomaly_id": anomaly["id"], "window_hours": 72},
    )
    affected = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()["affected_samples"]
    target_ids = [s["sample_id"] for s in affected if s["status"] == "proposed"]
    assert parent["id"] in target_ids and child_a["id"] in target_ids
    confirm = client.post(
        f"/api/investigations/{inv['id']}/affected/confirm",
        headers=admin["headers"],
        json={"items": [{"sample_id": sid, "measure": "quarantine"} for sid in target_ids]},
    )
    assert confirm.status_code == 200, confirm.text

    applied = client.post(
        f"/api/investigations/{inv['id']}/measures/apply",
        headers=admin["headers"],
        json={"measure": "quarantine", "sample_ids": []},
    )
    assert applied.status_code == 200, applied.text
    assert set(applied.json()["applied"]) == set(target_ids)
    assert client.get(f"/api/samples/{parent['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"
    case = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()
    assert case["status"] == "contained"

    # 措施可安全重放
    replay = client.post(
        f"/api/investigations/{inv['id']}/measures/apply",
        headers=admin["headers"],
        json={"measure": "quarantine", "sample_ids": target_ids},
    )
    assert replay.json()["applied"] == [] and set(replay.json()["replayed"]) == set(target_ids)

    # 未完成动作和未解释样品阻止结案
    action = client.post(
        f"/api/investigations/{inv['id']}/actions",
        headers=admin["headers"],
        json={"step_code": "VERIFY-TEMP", "title": "复核冷链温度记录", "assignee_user_id": admin["body"]["user"]["id"]},
    )
    assert action.status_code == 201
    blocked = client.post(f"/api/investigations/{inv['id']}/closure/request", headers=admin["headers"], json={"summary": ""})
    assert blocked.status_code == 409

    # 完成动作、逐项解释
    done = client.post(
        f"/api/investigations/{inv['id']}/actions/{action.json()['id']}/complete",
        headers=admin["headers"],
        json={"result": "温度曲线异常已确认"},
    )
    assert done.status_code == 200
    for sid in target_ids:
        explained = client.post(
            f"/api/investigations/{inv['id']}/affected/{sid}/explain",
            headers=admin["headers"],
            json={"note": f"样品 {sid} 经复检合格，可解除隔离"},
        )
        assert explained.status_code == 200

    requested = client.post(
        f"/api/investigations/{inv['id']}/closure/request", headers=admin["headers"], json={"summary": "来源查明"}
    )
    assert requested.status_code == 200
    assert requested.json()["status"] == "pending_closure"

    # 创建人本人不能批准
    own = client.post(
        f"/api/investigations/{inv['id']}/closure/decision",
        headers=admin["headers"],
        json={"decision": "approve", "comment": "同意"},
    )
    assert own.status_code == 409

    approver = _second_approver(client, admin)
    approved = client.post(
        f"/api/investigations/{inv['id']}/closure/decision",
        headers=approver["headers"],
        json={"decision": "approve", "comment": "复核证据链完整，同意解除"},
    )
    assert approved.status_code == 200, approved.text
    final = approved.json()
    assert final["status"] == "closed"
    assert final["release_approved_by"] == approver["id"]
    assert client.get(f"/api/samples/{parent['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "available"
    assert all(s["measure_status"] == "lifted" for s in final["affected_samples"])


def test_closure_rejection_returns_case_to_work(client, admin):
    _, _, parent, _, _ = _make_batch_samples(client, admin)
    anomaly = _anomaly(client, admin, sample_id=parent["id"])
    inv = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={
            "title": "驳回流程", "severity": "medium",
            "owner_user_id": admin["body"]["user"]["id"], "anomaly_ids": [anomaly["id"]],
        },
    ).json()
    affected = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()["affected_samples"]
    sid = affected[0]["sample_id"]
    client.post(
        f"/api/investigations/{inv['id']}/affected/confirm",
        headers=admin["headers"],
        json={"items": [{"sample_id": sid, "measure": "observe"}]},
    )
    observe = client.post(
        f"/api/investigations/{inv['id']}/measures/apply",
        headers=admin["headers"],
        json={"measure": "observe", "sample_ids": [sid]},
    )
    assert observe.status_code == 200, observe.text
    client.post(
        f"/api/investigations/{inv['id']}/affected/{sid}/explain",
        headers=admin["headers"],
        json={"note": "已解释处置结论"},
    )
    client.post(f"/api/investigations/{inv['id']}/closure/request", headers=admin["headers"], json={"summary": "申请"})
    approver = _second_approver(client, admin, username="approver3")
    rejected = client.post(
        f"/api/investigations/{inv['id']}/closure/decision",
        headers=approver["headers"],
        json={"decision": "reject", "comment": "证据不足，继续观察"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "observing"
    assert rejected.json()["release_approved_by"] is None


def test_evidence_versions_and_steps_are_idempotent(client, admin):
    inv = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={"title": "证据版本案件", "severity": "low", "owner_user_id": admin["body"]["user"]["id"]},
    ).json()
    payload = {"source_type": "温度记录仪", "source_reference": "LOGGER-7", "note": "12 点出现峰值", "idempotency_key": "ev-1"}
    first = client.post(f"/api/investigations/{inv['id']}/evidence", headers=admin["headers"], json=payload)
    second = client.post(f"/api/investigations/{inv['id']}/evidence", headers=admin["headers"], json=payload)
    assert first.json()["id"] == second.json()["id"] == 1
    assert second.json()["version"] == 1

    more = client.post(
        f"/api/investigations/{inv['id']}/evidence",
        headers=admin["headers"],
        json={"source_type": "照片", "note": "标签特写"},
    )
    assert more.json()["version"] == 2
    detail = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()
    assert detail["evidence_version"] == 2

    step = {"step_code": "RELABEL", "title": "重新打印标签"}
    s1 = client.post(f"/api/investigations/{inv['id']}/actions", headers=admin["headers"], json=step)
    s2 = client.post(f"/api/investigations/{inv['id']}/actions", headers=admin["headers"], json=step)
    assert s1.json()["id"] == s2.json()["id"]
    assert s2.json()["replayed"] is True


def test_overdue_sweep_and_scan_jobs_are_safe_to_rerun(client, admin):
    from app.database import transaction
    from app.investigations.jobs import InvestigationJobs, run_pending_jobs

    _, _, parent, child_a, _ = _make_batch_samples(client, admin)
    anomaly = _anomaly(client, admin, sample_id=parent["id"])
    inv = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={
            "title": "逾期案件", "severity": "high",
            "owner_user_id": admin["body"]["user"]["id"],
            "due_at": "2000-01-01T00:00:00+00:00",
        },
    ).json()

    with transaction(immediate=True) as connection:
        jobs = InvestigationJobs(connection)
        scan = jobs.enqueue_scan(inv["id"], {"seed_anomaly_id": anomaly["id"], "window_hours": 72})
        sweep = jobs.enqueue_overdue_sweep()
        # 重复入队被去重
        again = jobs.enqueue_scan(inv["id"], {"seed_anomaly_id": anomaly["id"], "window_hours": 72})
        assert again["id"] == scan["id"]
        sweep_again = jobs.enqueue_overdue_sweep()
        assert sweep_again["id"] == sweep["id"]

    with transaction(immediate=True) as connection:
        results = run_pending_jobs(connection)
    assert len(results) == 2
    assert all("error" not in r for r in results), results

    detail = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()
    sample_ids = [s["sample_id"] for s in detail["affected_samples"]]
    assert parent["id"] in sample_ids
    journal_types = [j["event_type"] for j in detail["journal"]]
    assert "overdue_flagged" in journal_types
    assert "candidates_scanned" in journal_types
    journal_count_before = len(detail["journal"])
    link_count_before = len(detail["anomaly_links"])
    affected_count_before = len(detail["affected_samples"])

    # 模拟租约过期后同一任务被再次投递：直接重放处理过程
    with transaction(immediate=True) as connection:
        handler = InvestigationJobs(connection)
        scan_row = connection.execute("SELECT * FROM background_jobs WHERE id=?", (scan["id"],)).fetchone()
        sweep_row = connection.execute("SELECT * FROM background_jobs WHERE id=?", (sweep["id"],)).fetchone()
        handler.process_scan(dict(scan_row))
        handler.process_overdue(dict(sweep_row))

    detail2 = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()
    assert len(detail2["journal"]) == journal_count_before
    assert len(detail2["anomaly_links"]) == link_count_before
    assert len(detail2["affected_samples"]) == affected_count_before


def test_list_investigations_stably_shows_basis_and_pending_work(client, admin):
    _, _, parent, child_a, _ = _make_batch_samples(client, admin)
    anomaly = _anomaly(client, admin, sample_id=parent["id"])
    inv = client.post(
        "/api/investigations",
        headers=admin["headers"],
        json={
            "title": "列表展示案件", "severity": "high",
            "owner_user_id": admin["body"]["user"]["id"],
            "due_at": "2000-01-01T00:00:00+00:00",
            "anomaly_ids": [anomaly["id"]],
        },
    ).json()
    client.post(
        f"/api/investigations/{inv['id']}/actions",
        headers=admin["headers"],
        json={"step_code": "STEP-1", "title": "待办步骤", "due_at": "2000-01-02T00:00:00+00:00"},
    )

    overdue = client.get("/api/investigations?overdue=true", headers=admin["headers"])
    assert overdue.status_code == 200
    rows = overdue.json()
    assert any(r["id"] == inv["id"] and r["overdue"] is True for r in rows)
    match = next(r for r in rows if r["id"] == inv["id"])
    assert match["pending_action_count"] == 1

    detail = client.get(f"/api/investigations/{inv['id']}", headers=admin["headers"]).json()
    assert detail["overdue_action_count"] == 1
    assert detail["actions"][0]["overdue"] is True
