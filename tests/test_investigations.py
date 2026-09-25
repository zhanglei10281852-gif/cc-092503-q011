from __future__ import annotations

from datetime import UTC, datetime

from app.core.clock import FrozenClock


def make_user(client, admin, username, role_codes):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "User!23456ab",
            "display_name": f"用户{username}",
            "role_codes": role_codes,
        },
    )
    assert response.status_code == 201, response.text
    login = client.post("/api/auth/login", json={"username": username, "password": "User!23456ab"})
    assert login.status_code == 200, login.text
    return {"headers": {"Authorization": f"Bearer {login.json()['token']}"}, "body": login.json()}


def make_location(client, admin, code, sensitivity="normal"):
    response = client.post(
        "/api/samples/locations",
        headers=admin["headers"],
        json={
            "code": code, "building": "科研楼", "room": "低温间", "cabinet": "柜一",
            "shelf": "二层", "sensitivity": sensitivity, "capacity_units": 200,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def make_batch(client, admin, code, expected=10):
    response = client.post(
        "/api/samples/batches",
        headers=admin["headers"],
        json={"batch_code": code, "project_code": "P-INV", "expected_count": expected},
    )
    assert response.status_code == 201, response.text
    return response.json()


def make_sample(client, admin, code, batch_id, location_id, quantity=50):
    response = client.post(
        "/api/samples",
        headers=admin["headers"],
        json={
            "sample_code": code, "batch_id": batch_id, "sample_type": "土壤",
            "quantity": quantity, "unit": "g", "location_id": location_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def make_anomaly(client, admin, *, sample_id=None, batch_id=None, anomaly_type="标签破损", severity="medium", description="标签脱落无法扫码"):
    response = client.post(
        "/api/samples/anomalies",
        headers=admin["headers"],
        json={
            "sample_id": sample_id, "batch_id": batch_id, "anomaly_type": anomaly_type,
            "severity": severity, "description": description,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def make_case(client, admin, *, severity="low", anomaly_ids=(), due_at=None, title="温控偏离联合调查"):
    payload = {
        "title": title,
        "hypothesis": "同一批样品受共同来源影响",
        "severity": severity,
        "owner_user_id": admin["body"]["user"]["id"],
        "anomaly_ids": list(anomaly_ids),
    }
    if due_at:
        payload["due_at"] = due_at
    response = client.post("/api/investigations", headers=admin["headers"], json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def get_detail(client, admin, case_id):
    response = client.get(f"/api/investigations/{case_id}", headers=admin["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def test_case_creation_links_anomalies_and_escalates_severity(client, admin):
    location = make_location(client, admin, "INV-L1")
    batch = make_batch(client, admin, "INV-B1")
    sample = make_sample(client, admin, "INV-S1", batch["id"], location["id"])
    first = make_anomaly(client, admin, sample_id=sample["id"], severity="high")
    second = make_anomaly(client, admin, batch_id=batch["id"], anomaly_type="数量差异", severity="medium", description="到货数量与单据不符")

    case = make_case(client, admin, severity="low", anomaly_ids=[first["id"], second["id"]])
    assert case["status"] == "investigating"
    assert case["severity"] == "high"  # 案件严重度升级到已确认异常的最高值
    assert case["owner_user_id"] == admin["body"]["user"]["id"]
    assert case["hypothesis"] == "同一批样品受共同来源影响"

    detail = get_detail(client, admin, case["id"])
    assert [link["anomaly_id"] for link in detail["links"]] == [first["id"], second["id"]]
    assert all(link["status"] == "confirmed" for link in detail["links"])
    assert all(link["basis"] == ["manual"] for link in detail["links"])
    anomalies = client.get("/api/samples/anomalies/list", headers=admin["headers"]).json()
    assert {item["state"] for item in anomalies} == {"investigating"}


def test_candidate_scan_covers_batch_location_lineage_and_time_window(client, admin):
    location_one = make_location(client, admin, "SCAN-L1")
    location_two = make_location(client, admin, "SCAN-L2")
    batch_one = make_batch(client, admin, "SCAN-B1")
    batch_two = make_batch(client, admin, "SCAN-B2")
    seed_sample = make_sample(client, admin, "SCAN-S1", batch_one["id"], location_one["id"])
    same_batch = make_sample(client, admin, "SCAN-S2", batch_one["id"], location_two["id"])
    same_location = make_sample(client, admin, "SCAN-S3", batch_two["id"], location_one["id"])
    unrelated = make_sample(client, admin, "SCAN-S4", batch_two["id"], location_two["id"])
    child = client.post(
        f"/api/samples/{seed_sample['id']}/aliquots",
        headers=admin["headers"],
        json={"requested_quantity": 10, "children": [{"sample_code": "SCAN-S1-A", "quantity": 10, "location_id": location_two["id"]}]},
    )
    assert child.status_code == 201, child.text
    child_id = child.json()["children"][0]["id"]

    seed = make_anomaly(client, admin, sample_id=seed_sample["id"], anomaly_type="温控偏离", severity="high", description="运输途中温度超限")
    by_batch = make_anomaly(client, admin, sample_id=same_batch["id"], anomaly_type="标签破损", description="同批标签受潮")
    by_location = make_anomaly(client, admin, sample_id=same_location["id"], anomaly_type="标签破损", description="同柜标签受潮")
    by_lineage = make_anomaly(client, admin, sample_id=child_id, anomaly_type="数量差异", description="子样量异常")
    by_batch_only = make_anomaly(client, admin, batch_id=batch_two["id"], anomaly_type="数量差异", description="批次数量差异")
    old_unrelated = make_anomaly(client, admin, sample_id=unrelated["id"], anomaly_type="标签破损", description="无关样品")

    # 模拟一条十天前的无关异常：任何维度都不应关联
    from app.database import transaction

    with transaction(immediate=True) as connection:
        connection.execute(
            "UPDATE anomaly_cases SET created_at=? WHERE id=?",
            ("2026-09-10T00:00:00+00:00", old_unrelated["id"]),
        )

    case = make_case(client, admin, anomaly_ids=[seed["id"]])
    scan = client.post(f"/api/investigations/{case['id']}/scans", headers=admin["headers"], json={"window_hours": 24})
    assert scan.status_code == 200, scan.text
    created = scan.json()["created_anomaly_ids"]
    assert set(created) == {by_batch["id"], by_location["id"], by_lineage["id"], by_batch_only["id"]}
    assert old_unrelated["id"] not in created

    detail = get_detail(client, admin, case["id"])
    basis_by_anomaly = {link["anomaly_id"]: set(link["basis"]) for link in detail["links"] if link["status"] == "candidate"}
    assert basis_by_anomaly[by_batch["id"]] == {"batch", "time_window"}
    assert basis_by_anomaly[by_location["id"]] == {"location", "time_window"}
    assert basis_by_anomaly[by_lineage["id"]] == {"batch", "lineage", "time_window"}
    assert basis_by_anomaly[by_batch_only["id"]] == {"time_window"}
    batch_detail = next(link for link in detail["links"] if link["anomaly_id"] == by_batch["id"])["basis_detail"]
    assert batch_detail["batch"]["batch_ids"] == [batch_one["id"]]

    # 重复扫描安全重跑：不产生新候选、不更新已有关联
    again = client.post(f"/api/investigations/{case['id']}/scans", headers=admin["headers"], json={"window_hours": 24})
    assert again.status_code == 200
    assert again.json()["created_anomaly_ids"] == []
    assert again.json()["merged_anomaly_ids"] == []
    assert again.json()["candidate_count"] == 4


def test_dismissed_candidate_is_not_resurrected_by_rescan(client, admin):
    location = make_location(client, admin, "DIS-L1")
    batch = make_batch(client, admin, "DIS-B1")
    sample_one = make_sample(client, admin, "DIS-S1", batch["id"], location["id"])
    sample_two = make_sample(client, admin, "DIS-S2", batch["id"], location["id"])
    seed = make_anomaly(client, admin, sample_id=sample_one["id"])
    other = make_anomaly(client, admin, sample_id=sample_two["id"])
    case = make_case(client, admin, anomaly_ids=[seed["id"]])

    client.post(f"/api/investigations/{case['id']}/scans", headers=admin["headers"], json={})
    dismissed = client.post(f"/api/investigations/{case['id']}/links/{other['id']}/dismiss", headers=admin["headers"])
    assert dismissed.status_code == 200, dismissed.text
    assert dismissed.json()["status"] == "dismissed"

    rescan = client.post(f"/api/investigations/{case['id']}/scans", headers=admin["headers"], json={})
    assert rescan.json()["created_anomaly_ids"] == []
    assert rescan.json()["skipped_dismissed_ids"] == [other["id"]]
    detail = get_detail(client, admin, case["id"])
    assert next(link for link in detail["links"] if link["anomaly_id"] == other["id"])["status"] == "dismissed"


def test_confirm_and_unified_quarantine_is_idempotent(client, admin):
    location = make_location(client, admin, "Q-L1")
    batch = make_batch(client, admin, "Q-B1")
    sample_one = make_sample(client, admin, "Q-S1", batch["id"], location["id"])
    sample_two = make_sample(client, admin, "Q-S2", batch["id"], location["id"])
    seed = make_anomaly(client, admin, sample_id=sample_one["id"], anomaly_type="温控偏离", severity="critical", description="冷库温度超限")
    second = make_anomaly(client, admin, sample_id=sample_two["id"], anomaly_type="标签破损", description="同柜标签破损")
    case = make_case(client, admin, anomaly_ids=[seed["id"]])
    client.post(f"/api/investigations/{case['id']}/scans", headers=admin["headers"], json={})

    confirmed = client.post(
        f"/api/investigations/{case['id']}/links/confirm",
        headers=admin["headers"],
        json={"anomaly_ids": [second["id"]]},
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["case"]["severity"] == "critical"

    applied = client.post(
        f"/api/investigations/{case['id']}/measures/apply",
        headers=admin["headers"],
        json={"measure": "quarantine"},
    )
    assert applied.status_code == 200, applied.text
    assert sorted(applied.json()["applied_sample_ids"]) == sorted([sample_one["id"], sample_two["id"]])
    assert applied.json()["case"]["status"] == "measures_applied"

    for sample in (sample_one, sample_two):
        detail = client.get(f"/api/samples/{sample['id']}", headers=admin["headers"]).json()
        assert detail["lifecycle_state"] == "quarantined"
        assert detail["events"][-1]["event_type"] == "quarantined"

    # 隔离中禁止消耗与转移
    consumed = client.post(
        f"/api/samples/{sample_one['id']}/consumptions",
        headers=admin["headers"],
        json={"experiment_code": "EXP-Q", "quantity": 1, "idempotency_key": "q-consume-1"},
    )
    assert consumed.status_code == 409
    moved = client.post(
        f"/api/sample-operations/{sample_one['id']}/transfers",
        headers=admin["headers"],
        json={"location_id": location["id"], "expected_version": 2, "reason": "尝试转移"},
    )
    assert moved.status_code == 409

    # 重复执行措施安全：全部跳过，不产生重复记录
    reapplied = client.post(
        f"/api/investigations/{case['id']}/measures/apply",
        headers=admin["headers"],
        json={"measure": "quarantine"},
    )
    assert reapplied.status_code == 200
    assert reapplied.json()["applied_sample_ids"] == []
    assert sorted(reapplied.json()["skipped_sample_ids"]) == sorted([sample_one["id"], sample_two["id"]])
    detail = get_detail(client, admin, case["id"])
    assert len(detail["affected_samples"]) == 2
    assert all(row["measure"] == "quarantine" and row["measure_state"] == "active" for row in detail["affected_samples"])
    assert all(row["previous_lifecycle_state"] == "available" for row in detail["affected_samples"])


def test_observe_measure_keeps_state_and_upgrade_path(client, admin):
    location = make_location(client, admin, "OB-L1")
    batch = make_batch(client, admin, "OB-B1")
    sample = make_sample(client, admin, "OB-S1", batch["id"], location["id"])
    anomaly = make_anomaly(client, admin, sample_id=sample["id"], severity="medium")
    case = make_case(client, admin, anomaly_ids=[anomaly["id"]])

    observed = client.post(f"/api/investigations/{case['id']}/measures/apply", headers=admin["headers"], json={"measure": "observe"})
    assert observed.status_code == 200, observed.text
    assert observed.json()["applied_sample_ids"] == [sample["id"]]
    assert client.get(f"/api/samples/{sample['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "available"

    # 观察可升级为隔离，隔离不能降级为观察
    upgraded = client.post(f"/api/investigations/{case['id']}/measures/apply", headers=admin["headers"], json={"measure": "quarantine"})
    assert upgraded.status_code == 200
    assert upgraded.json()["upgraded_sample_ids"] == [sample["id"]]
    assert client.get(f"/api/samples/{sample['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"
    downgraded = client.post(f"/api/investigations/{case['id']}/measures/apply", headers=admin["headers"], json={"measure": "observe"})
    assert downgraded.status_code == 409


def test_severity_escalation_survives_stale_and_lower_updates(client, admin):
    anomaly = make_anomaly(client, admin, batch_id=make_batch(client, admin, "SEV-B1")["id"], anomaly_type="数量差异", severity="low", description="轻微数量差异")
    case = make_case(client, admin, severity="low", anomaly_ids=[anomaly["id"]])

    escalated = client.patch(
        f"/api/investigations/{case['id']}",
        headers=admin["headers"],
        json={"severity": "high", "expected_version": case["version"]},
    )
    assert escalated.status_code == 200, escalated.text
    assert escalated.json()["severity"] == "high"
    assert escalated.json()["severity_applied"] is True

    # 携带更低严重度的更新不会覆盖已升级结果
    lowered = client.patch(
        f"/api/investigations/{case['id']}",
        headers=admin["headers"],
        json={"severity": "medium", "hypothesis": "更新假设但不降级", "expected_version": escalated.json()["version"]},
    )
    assert lowered.status_code == 200, lowered.text
    assert lowered.json()["severity"] == "high"
    assert lowered.json()["severity_applied"] is False
    assert lowered.json()["hypothesis"] == "更新假设但不降级"

    # 旧版本号的更新整体被拒绝
    stale = client.patch(
        f"/api/investigations/{case['id']}",
        headers=admin["headers"],
        json={"severity": "low", "expected_version": case["version"]},
    )
    assert stale.status_code == 409
    assert get_detail(client, admin, case["id"])["case"]["severity"] == "high"


def test_evidence_versions_and_steps_are_ordered(client, admin):
    anomaly = make_anomaly(client, admin, batch_id=make_batch(client, admin, "EV-B1")["id"], anomaly_type="温控偏离", severity="medium", description="温度记录缺失")
    case = make_case(client, admin, anomaly_ids=[anomaly["id"]])
    for index in range(3):
        response = client.post(
            f"/api/investigations/{case['id']}/evidence",
            headers=admin["headers"],
            json={"content": f"第 {index + 1} 版证据", "source_uri": f"lab-notebook:{index + 1}"},
        )
        assert response.status_code == 201, response.text
        assert response.json()["version_no"] == index + 1

    step = client.post(
        f"/api/investigations/{case['id']}/steps",
        headers=admin["headers"],
        json={"description": "复核温控记录仪原始数据", "due_at": "2026-10-01T00:00:00+00:00"},
    )
    assert step.status_code == 201, step.text
    assert step.json()["step_no"] == 1
    completed = client.post(f"/api/investigations/{case['id']}/steps/{step.json()['id']}/complete", headers=admin["headers"])
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "done"
    again = client.post(f"/api/investigations/{case['id']}/steps/{step.json()['id']}/complete", headers=admin["headers"])
    assert again.status_code == 409

    detail = get_detail(client, admin, case["id"])
    assert [item["version_no"] for item in detail["evidence"]] == [1, 2, 3]
    assert detail["steps"][0]["status"] == "done"
    assert detail["pending_actions"]["pending_step_ids"] == []


def _prepare_closable_case(client, admin):
    location = make_location(client, admin, "CL-L1")
    batch = make_batch(client, admin, "CL-B1")
    sample_one = make_sample(client, admin, "CL-S1", batch["id"], location["id"])
    sample_two = make_sample(client, admin, "CL-S2", batch["id"], location["id"])
    first = make_anomaly(client, admin, sample_id=sample_one["id"], anomaly_type="温控偏离", severity="high", description="温度超限")
    second = make_anomaly(client, admin, sample_id=sample_two["id"], anomaly_type="标签破损", description="标签破损")
    case = make_case(client, admin, anomaly_ids=[first["id"], second["id"]])
    client.post(f"/api/investigations/{case['id']}/measures/apply", headers=admin["headers"], json={"measure": "quarantine"})
    return case, [sample_one, sample_two], [first, second]


def test_close_requires_dispositions_and_second_person_release(client, admin):
    case, samples, anomalies = _prepare_closable_case(client, admin)
    case_id = case["id"]

    # 未逐项解释前禁止结案
    premature = client.post(f"/api/investigations/{case_id}/close-requests", headers=admin["headers"], json={"note": "拟结案"})
    assert premature.status_code == 409
    assert premature.json()["error"]["context"]["samples_missing_disposition_ids"] == [sample["id"] for sample in samples]

    for sample in samples:
        disposition = client.post(
            f"/api/investigations/{case_id}/samples/{sample['id']}/disposition",
            headers=admin["headers"],
            json={"note": f"样品 {sample['sample_code']} 复检合格，解除隔离"},
        )
        assert disposition.status_code == 200, disposition.text

    requested = client.post(f"/api/investigations/{case_id}/close-requests", headers=admin["headers"], json={"note": "调查完成"})
    assert requested.status_code == 200, requested.text
    assert requested.json()["status"] == "release_pending"

    # 申请人自己不能批准解除，必须由另一名人员批准
    own = client.post(f"/api/investigations/{case_id}/release-decisions", headers=admin["headers"], json={"decision": "approve"})
    assert own.status_code == 422

    approver = make_user(client, admin, "release-approver", ["approver"])
    approved = client.post(
        f"/api/investigations/{case_id}/release-decisions",
        headers=approver["headers"],
        json={"decision": "approve", "comment": "证据充分，同意解除"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["case"]["status"] == "closed"
    assert sorted(approved.json()["released_sample_ids"]) == sorted(sample["id"] for sample in samples)

    for sample in samples:
        detail = client.get(f"/api/samples/{sample['id']}", headers=admin["headers"]).json()
        assert detail["lifecycle_state"] == "available"
        assert detail["events"][-1]["event_type"] == "quarantine.released"
    anomaly_states = {item["id"]: item["state"] for item in client.get("/api/samples/anomalies/list", headers=admin["headers"]).json()}
    assert all(anomaly_states[anomaly["id"]] == "resolved" for anomaly in anomalies)

    detail = get_detail(client, admin, case_id)
    assert all(row["measure_state"] == "released" for row in detail["affected_samples"])
    assert detail["pending_actions"]["active_measure_sample_ids"] == []
    assert detail["release_decisions"][0]["decision"] == "approved"


def test_release_rejection_returns_case_to_measures_applied(client, admin):
    case, samples, _ = _prepare_closable_case(client, admin)
    case_id = case["id"]
    for sample in samples:
        client.post(
            f"/api/investigations/{case_id}/samples/{sample['id']}/disposition",
            headers=admin["headers"],
            json={"note": "已逐项说明"},
        )
    client.post(f"/api/investigations/{case_id}/close-requests", headers=admin["headers"], json={})
    approver = make_user(client, admin, "reject-approver", ["approver"])
    rejected = client.post(
        f"/api/investigations/{case_id}/release-decisions",
        headers=approver["headers"],
        json={"decision": "reject", "comment": "第 2 份样品解释不充分"},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["case"]["status"] == "measures_applied"
    assert client.get(f"/api/samples/{samples[0]['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"

    # 补充说明后可再次申请结案
    again = client.post(f"/api/investigations/{case_id}/close-requests", headers=admin["headers"], json={"note": "补充后再次申请"})
    assert again.status_code == 200
    assert again.json()["status"] == "release_pending"


def test_release_requires_approval_permission(client, admin):
    case, samples, _ = _prepare_closable_case(client, admin)
    case_id = case["id"]
    for sample in samples:
        client.post(
            f"/api/investigations/{case_id}/samples/{sample['id']}/disposition",
            headers=admin["headers"],
            json={"note": "已说明"},
        )
    client.post(f"/api/investigations/{case_id}/close-requests", headers=admin["headers"], json={})
    researcher = make_user(client, admin, "plain-researcher", ["researcher"])
    denied = client.post(
        f"/api/investigations/{case_id}/release-decisions",
        headers=researcher["headers"],
        json={"decision": "approve"},
    )
    assert denied.status_code == 403


def test_close_blocked_by_pending_candidates(client, admin):
    location = make_location(client, admin, "PC-L1")
    batch = make_batch(client, admin, "PC-B1")
    sample_one = make_sample(client, admin, "PC-S1", batch["id"], location["id"])
    sample_two = make_sample(client, admin, "PC-S2", batch["id"], location["id"])
    seed = make_anomaly(client, admin, sample_id=sample_one["id"])
    other = make_anomaly(client, admin, sample_id=sample_two["id"])
    case = make_case(client, admin, anomaly_ids=[seed["id"]])
    client.post(f"/api/investigations/{case['id']}/scans", headers=admin["headers"], json={})
    client.post(f"/api/investigations/{case['id']}/measures/apply", headers=admin["headers"], json={"measure": "observe"})
    client.post(
        f"/api/investigations/{case['id']}/samples/{sample_one['id']}/disposition",
        headers=admin["headers"],
        json={"note": "已说明"},
    )
    blocked = client.post(f"/api/investigations/{case['id']}/close-requests", headers=admin["headers"], json={})
    assert blocked.status_code == 409
    assert blocked.json()["error"]["context"]["pending_candidate_anomaly_ids"] == [other["id"]]

    client.post(f"/api/investigations/{case['id']}/links/{other['id']}/dismiss", headers=admin["headers"])
    allowed = client.post(f"/api/investigations/{case['id']}/close-requests", headers=admin["headers"], json={})
    assert allowed.status_code == 200, allowed.text


def test_overdue_check_is_idempotent_and_due_extension_clears_flag(client, admin):
    anomaly = make_anomaly(client, admin, batch_id=make_batch(client, admin, "OD-B1")["id"], anomaly_type="温控偏离", severity="medium", description="温度偏离")
    case = make_case(client, admin, anomaly_ids=[anomaly["id"]], due_at="2026-09-01T00:00:00+00:00")

    first = client.post("/api/investigations/overdue-checks", headers=admin["headers"])
    assert first.status_code == 200, first.text
    assert first.json()["marked_case_ids"] == [case["id"]]
    second = client.post("/api/investigations/overdue-checks", headers=admin["headers"])
    assert second.json()["marked_case_ids"] == []  # 重复执行安全

    detail = get_detail(client, admin, case["id"])
    assert detail["case"]["overdue"] == 1
    assert detail["pending_actions"]["overdue"] is True
    overdue_list = client.get("/api/investigations?overdue=true", headers=admin["headers"]).json()
    assert [item["id"] for item in overdue_list] == [case["id"]]

    extended = client.patch(
        f"/api/investigations/{case['id']}",
        headers=admin["headers"],
        json={"due_at": "2030-01-01T00:00:00+00:00", "expected_version": detail["case"]["version"]},
    )
    assert extended.status_code == 200, extended.text
    assert extended.json()["overdue"] == 0


def test_scan_jobs_deduplicate_and_run_due_executes(client, admin):
    location = make_location(client, admin, "JOB-L1")
    batch = make_batch(client, admin, "JOB-B1")
    sample_one = make_sample(client, admin, "JOB-S1", batch["id"], location["id"])
    sample_two = make_sample(client, admin, "JOB-S2", batch["id"], location["id"])
    seed = make_anomaly(client, admin, sample_id=sample_one["id"])
    other = make_anomaly(client, admin, sample_id=sample_two["id"])
    case = make_case(client, admin, anomaly_ids=[seed["id"]])

    first = client.post(f"/api/investigations/{case['id']}/scan-jobs", headers=admin["headers"], json={"scan_token": "round-1"})
    assert first.status_code == 201, first.text
    duplicate = client.post(f"/api/investigations/{case['id']}/scan-jobs", headers=admin["headers"], json={"scan_token": "round-1"})
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == first.json()["id"]  # 重复扫描任务被去重

    run = client.post("/api/investigations/jobs/run-due", headers=admin["headers"])
    assert run.status_code == 200, run.text
    assert len(run.json()["processed"]) == 1
    assert run.json()["processed"][0]["status"] == "completed"
    assert run.json()["processed"][0]["result"]["created_anomaly_ids"] == [other["id"]]

    idle = client.post("/api/investigations/jobs/run-due", headers=admin["headers"])
    assert idle.json()["processed"] == []

    overdue_first = client.post("/api/investigations/overdue-check-jobs", headers=admin["headers"])
    overdue_second = client.post("/api/investigations/overdue-check-jobs", headers=admin["headers"])
    assert overdue_first.json()["id"] == overdue_second.json()["id"]
    run = client.post("/api/investigations/jobs/run-due", headers=admin["headers"])
    assert [item["job_type"] for item in run.json()["processed"]] == ["investigation.overdue_check"]


def test_stale_claimed_scan_job_is_safely_rerunnable(client, admin):
    """逾期（租约过期）的扫描任务被重新领取后重跑不产生重复候选。"""
    from app.database import transaction
    from app.services.jobs import JobService
    from app.samples.investigations import InvestigationJobHandler

    clock = FrozenClock(datetime(2026, 9, 25, 8, 30, tzinfo=UTC))
    with transaction(immediate=True) as connection:
        location_id = connection.execute(
            "INSERT INTO storage_locations(code,building,room,cabinet,shelf,sensitivity,capacity_units,created_at,updated_at) "
            "VALUES('STALE-L1','楼','室','柜','层','normal',10,'2026-09-25T08:00:00+00:00','2026-09-25T08:00:00+00:00')"
        ).lastrowid
        batch_id = connection.execute(
            "INSERT INTO receipt_batches(batch_code,project_code,received_by,received_at,expected_count,status,qr_payload,created_at,updated_at) "
            "VALUES('STALE-B1','P',1,'2026-09-25T08:00:00+00:00',2,'open','qr-stale','2026-09-25T08:00:00+00:00','2026-09-25T08:00:00+00:00')"
        ).lastrowid
        sample_ids = []
        for code in ("STALE-S1", "STALE-S2"):
            sample_ids.append(connection.execute(
                "INSERT INTO samples(sample_code,batch_id,sample_type,quantity,unit,lifecycle_state,location_id,lineage_depth,created_at,updated_at) "
                f"VALUES('{code}',{batch_id},'土壤',10,'g','available',{location_id},0,'2026-09-25T08:00:00+00:00','2026-09-25T08:00:00+00:00')"
            ).lastrowid)
        anomaly_ids = []
        for index, sample_id in enumerate(sample_ids):
            anomaly_ids.append(connection.execute(
                "INSERT INTO anomaly_cases(case_code,sample_id,anomaly_type,severity,state,detected_by,description,created_at,updated_at) "
                f"VALUES('STALE-A{index}',{sample_id},'标签破损','medium','open',1,'标签破损','2026-09-25T08:01:00+00:00','2026-09-25T08:01:00+00:00')"
            ).lastrowid)
        case_id = connection.execute(
            "INSERT INTO investigation_cases(case_code,title,severity,status,owner_user_id,created_by,created_at,updated_at) "
            "VALUES('STALE-C1','租约过期重跑','medium','investigating',1,1,'2026-09-25T08:02:00+00:00','2026-09-25T08:02:00+00:00')"
        ).lastrowid
        connection.execute(
            "INSERT INTO investigation_case_links(case_id,anomaly_id,status,basis_json,created_at,updated_at) "
            f"VALUES({case_id},{anomaly_ids[0]},'confirmed','[\"manual\"]','2026-09-25T08:02:00+00:00','2026-09-25T08:02:00+00:00')"
        )

        jobs = JobService(connection, clock)
        handler = InvestigationJobHandler(connection, clock)
        job = jobs.enqueue("investigation.candidate_scan", f"investigation.candidate_scan:{case_id}:stale", {"case_id": case_id, "window_hours": 24})
        first_claim = jobs.claim("worker-1", lease_seconds=60)
        assert first_claim["id"] == job["id"]
        clock.advance(seconds=120)  # worker-1 租约过期，任务变为逾期任务
        second_claim = jobs.claim("worker-2", lease_seconds=60)
        assert second_claim["id"] == job["id"]

        first_run = handler.execute(second_claim["job_type"], {"case_id": case_id, "window_hours": 24})
        assert first_run["created_anomaly_ids"] == [anomaly_ids[1]]
        jobs.complete(job["id"], "worker-2", first_run)
        rerun = handler.execute("investigation.candidate_scan", {"case_id": case_id, "window_hours": 24})
        assert rerun["created_anomaly_ids"] == []  # 安全重跑：无重复候选
        count = connection.execute(
            "SELECT COUNT(*) FROM investigation_case_links WHERE case_id=? AND anomaly_id=?",
            (case_id, anomaly_ids[1]),
        ).fetchone()[0]
        assert count == 1


def test_detail_response_is_stable_and_shows_basis_and_pending_actions(client, admin):
    location = make_location(client, admin, "ST-L1")
    batch = make_batch(client, admin, "ST-B1")
    sample_one = make_sample(client, admin, "ST-S1", batch["id"], location["id"])
    sample_two = make_sample(client, admin, "ST-S2", batch["id"], location["id"])
    seed = make_anomaly(client, admin, sample_id=sample_one["id"], anomaly_type="温控偏离", severity="high", description="温度超限")
    other = make_anomaly(client, admin, sample_id=sample_two["id"], anomaly_type="标签破损", description="标签破损")
    case = make_case(client, admin, anomaly_ids=[seed["id"]])
    client.post(f"/api/investigations/{case['id']}/scans", headers=admin["headers"], json={})
    client.post(f"/api/investigations/{case['id']}/measures/apply", headers=admin["headers"], json={"measure": "observe"})
    client.post(f"/api/investigations/{case['id']}/steps", headers=admin["headers"], json={"description": "待办步骤"})

    first = get_detail(client, admin, case["id"])
    second = get_detail(client, admin, case["id"])
    assert first == second  # 查询结果稳定

    candidate = next(link for link in first["links"] if link["anomaly_id"] == other["id"])
    assert candidate["status"] == "candidate"
    assert set(candidate["basis"]) == {"batch", "location", "time_window"}
    confirmed = next(link for link in first["links"] if link["anomaly_id"] == seed["id"])
    assert confirmed["basis"] == ["manual"]

    pending = first["pending_actions"]
    assert pending["unconfirmed_candidate_anomaly_ids"] == [other["id"]]
    assert pending["samples_missing_disposition_ids"] == [sample_one["id"]]
    assert pending["pending_step_ids"] == [first["steps"][0]["id"]]
    assert pending["active_measure_sample_ids"] == [sample_one["id"]]


def test_quarantine_release_respects_other_open_cases(client, admin):
    location = make_location(client, admin, "SH-L1")
    batch = make_batch(client, admin, "SH-B1")
    sample = make_sample(client, admin, "SH-S1", batch["id"], location["id"])
    anomaly_one = make_anomaly(client, admin, sample_id=sample["id"], anomaly_type="温控偏离", severity="high", description="第一起异常")
    anomaly_two = make_anomaly(client, admin, sample_id=sample["id"], anomaly_type="标签破损", severity="medium", description="第二起异常")
    approver = make_user(client, admin, "shared-approver", ["approver"])

    case_one = make_case(client, admin, anomaly_ids=[anomaly_one["id"]])
    client.post(f"/api/investigations/{case_one['id']}/measures/apply", headers=admin["headers"], json={"measure": "quarantine"})
    case_two = make_case(client, admin, anomaly_ids=[anomaly_two["id"]])
    client.post(f"/api/investigations/{case_two['id']}/measures/apply", headers=admin["headers"], json={"measure": "quarantine"})

    def close_case(case_id):
        client.post(
            f"/api/investigations/{case_id}/samples/{sample['id']}/disposition",
            headers=admin["headers"],
            json={"note": "已说明"},
        )
        client.post(f"/api/investigations/{case_id}/close-requests", headers=admin["headers"], json={})
        client.post(f"/api/investigations/{case_id}/release-decisions", headers=approver["headers"], json={"decision": "approve"})

    close_case(case_one["id"])
    # 第一个案件结案时第二个案件仍在隔离该样品，状态保持隔离
    assert get_detail(client, admin, case_one["id"])["case"]["status"] == "closed"
    assert client.get(f"/api/samples/{sample['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"
    close_case(case_two["id"])
    assert get_detail(client, admin, case_two["id"])["case"]["status"] == "closed"
    assert client.get(f"/api/samples/{sample['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "available"


def test_dismiss_case_reverts_anomaly_state(client, admin):
    anomaly = make_anomaly(client, admin, batch_id=make_batch(client, admin, "DM-B1")["id"], anomaly_type="数量差异", severity="low", description="误报记录")
    case = make_case(client, admin, anomaly_ids=[anomaly["id"]])
    dismissed = client.post(
        f"/api/investigations/{case['id']}/dismiss",
        headers=admin["headers"],
        json={"reason": "复核确认为误报"},
    )
    assert dismissed.status_code == 200, dismissed.text
    assert dismissed.json()["status"] == "dismissed"
    anomaly_state = {item["id"]: item["state"] for item in client.get("/api/samples/anomalies/list", headers=admin["headers"]).json()}
    assert anomaly_state[anomaly["id"]] == "open"
