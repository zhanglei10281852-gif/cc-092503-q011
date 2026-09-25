from __future__ import annotations

import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import NotFoundError, ValidationError
from app.core.security import Principal


class AssociationService:
    """根据接收批次、位置、谱系祖先和时间窗口生成候选关联。

    该服务只读且无副作用：候选必须经人工确认后才会写入案件，因此重复扫描可以安全重跑。
    """

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()

    def propose(self, principal: Principal, query: dict[str, Any]) -> dict[str, Any]:
        principal.require("samples.read")
        seed = self._seed_context(query)
        window_from, window_to = self._window(query, seed)

        batch_id = query.get("batch_id") or seed.get("batch_id")
        location_id = query.get("location_id") or seed.get("location_id")
        root_sample_id = query.get("root_sample_id") or seed.get("root_sample_id")

        dimensions = []
        if batch_id:
            dimensions.append({"type": "batch", "batch_id": batch_id, "label": self._batch_label(batch_id)})
        if location_id:
            dimensions.append({"type": "location", "location_id": location_id, "label": self._location_label(location_id)})
        if root_sample_id:
            dimensions.append({"type": "lineage", "root_sample_id": root_sample_id, "label": self._sample_label(root_sample_id)})
        dimensions.append({
            "type": "time_window",
            "from": window_from,
            "to": window_to,
            "window_hours": query.get("window_hours", 72),
        })
        if len(dimensions) == 1:
            raise ValidationError("至少提供一个关联维度：接收批次、位置或谱系祖先")

        anomaly_candidates = self._anomaly_candidates(
            batch_id, location_id, root_sample_id, window_from, window_to, seed.get("anomaly_id")
        )
        sample_candidates = self._sample_candidates(
            batch_id, location_id, root_sample_id, window_from, window_to, seed.get("sample_id")
        )
        return {
            "dimensions": dimensions,
            "window": {"from": window_from, "to": window_to},
            "anomaly_candidates": anomaly_candidates,
            "sample_candidates": sample_candidates,
        }

    # ------------------------------------------------------------------ seeds
    def _seed_context(self, query: dict[str, Any]) -> dict[str, Any]:
        seed: dict[str, Any] = {}
        if query.get("seed_anomaly_id"):
            row = self.connection.execute(
                """SELECT a.*,s.batch_id AS sample_batch_id,s.location_id,s.root_sample_id
                   FROM anomaly_cases a
                   LEFT JOIN samples s ON s.id=a.sample_id
                   WHERE a.id=?""",
                (query["seed_anomaly_id"],),
            ).fetchone()
            if not row:
                raise NotFoundError("种子异常不存在")
            seed["anomaly_id"] = row["id"]
            seed["sample_id"] = row["sample_id"]
            seed["batch_id"] = row["batch_id"] or row["sample_batch_id"]
            seed["location_id"] = row["location_id"]
            seed["root_sample_id"] = row["root_sample_id"]
            seed["timestamp"] = from_storage(row["created_at"])
        elif query.get("seed_sample_id"):
            row = self.connection.execute(
                "SELECT * FROM samples WHERE id=?", (query["seed_sample_id"],)
            ).fetchone()
            if not row:
                raise NotFoundError("种子样品不存在")
            seed["sample_id"] = row["id"]
            seed["batch_id"] = row["batch_id"]
            seed["location_id"] = row["location_id"]
            seed["root_sample_id"] = row["root_sample_id"] or row["id"]
            seed["timestamp"] = from_storage(row["created_at"])
        return seed

    def _window(self, query: dict[str, Any], seed: dict[str, Any]) -> tuple[str, str]:
        if query.get("occurred_from") and query.get("occurred_to"):
            return query["occurred_from"], query["occurred_to"]
        anchor = seed.get("timestamp") or self.clock.now()
        hours = query.get("window_hours", 72)
        return to_storage(anchor - timedelta(hours=hours)), to_storage(anchor + timedelta(hours=hours))

    # -------------------------------------------------------------- candidates
    def _anomaly_candidates(
        self,
        batch_id: int | None,
        location_id: int | None,
        root_sample_id: int | None,
        window_from: str,
        window_to: str,
        seed_anomaly_id: int | None,
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT a.*,s.batch_id AS sample_batch_id,s.location_id,s.root_sample_id,
                      b.batch_code,l.code AS location_code,root_s.sample_code AS root_sample_code
               FROM anomaly_cases a
               LEFT JOIN samples s ON s.id=a.sample_id
               LEFT JOIN receipt_batches b ON b.id=COALESCE(a.batch_id,s.batch_id)
               LEFT JOIN storage_locations l ON l.id=s.location_id
               LEFT JOIN samples root_s ON root_s.id=s.root_sample_id
               WHERE a.state NOT IN ('resolved','dismissed')
               ORDER BY a.created_at,a.id""",
        ).fetchall()
        candidates: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            reasons: list[dict[str, Any]] = []
            same_batch = batch_id and (item["batch_id"] == batch_id or item["sample_batch_id"] == batch_id)
            if same_batch:
                reasons.append({"type": "batch", "batch_id": batch_id, "label": item["batch_code"]})
            if location_id and item["location_id"] == location_id:
                reasons.append({"type": "location", "location_id": location_id, "label": item["location_code"]})
            if root_sample_id and item["root_sample_id"] == root_sample_id:
                reasons.append({"type": "lineage", "root_sample_id": root_sample_id, "label": item["root_sample_code"]})
            if window_from <= item["created_at"] <= window_to:
                reasons.append({"type": "time_window", "at": item["created_at"]})
            if not reasons:
                continue
            if item["id"] == seed_anomaly_id:
                reasons.append({"type": "seed", "label": "种子异常"})
            candidates.append({
                "anomaly_id": item["id"],
                "case_code": item["case_code"],
                "anomaly_type": item["anomaly_type"],
                "severity": item["severity"],
                "state": item["state"],
                "sample_id": item["sample_id"],
                "batch_id": item["batch_id"] or item["sample_batch_id"],
                "created_at": item["created_at"],
                "is_seed": item["id"] == seed_anomaly_id,
                "basis": reasons,
            })
        return candidates

    def _sample_candidates(
        self,
        batch_id: int | None,
        location_id: int | None,
        root_sample_id: int | None,
        window_from: str,
        window_to: str,
        seed_sample_id: int | None,
    ) -> list[dict[str, Any]]:
        # 时间窗口命中的异常所指向的样品集合
        window_anomaly_samples = {
            row[0]
            for row in self.connection.execute(
                "SELECT DISTINCT sample_id FROM anomaly_cases "
                "WHERE sample_id IS NOT NULL AND created_at BETWEEN ? AND ? "
                "AND state NOT IN ('resolved','dismissed')",
                (window_from, window_to),
            ).fetchall()
        }
        rows = self.connection.execute(
            """SELECT s.*,b.batch_code,l.code AS location_code,root_s.sample_code AS root_sample_code
               FROM samples s
               JOIN receipt_batches b ON b.id=s.batch_id
               LEFT JOIN storage_locations l ON l.id=s.location_id
               LEFT JOIN samples root_s ON root_s.id=s.root_sample_id
               WHERE s.lifecycle_state NOT IN ('destroyed')
               ORDER BY s.sample_code,s.id""",
        ).fetchall()
        candidates: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            reasons: list[dict[str, Any]] = []
            if batch_id and item["batch_id"] == batch_id:
                reasons.append({"type": "batch", "batch_id": batch_id, "label": item["batch_code"]})
            if location_id and item["location_id"] == location_id:
                reasons.append({"type": "location", "location_id": location_id, "label": item["location_code"]})
            if root_sample_id and item["root_sample_id"] == root_sample_id:
                reasons.append({"type": "lineage", "root_sample_id": root_sample_id, "label": item["root_sample_code"]})
            if item["id"] in window_anomaly_samples:
                reasons.append({"type": "time_window", "label": "窗口内存在异常记录"})
            if not reasons:
                continue
            if item["id"] == seed_sample_id:
                reasons.append({"type": "seed", "label": "种子样品"})
            candidates.append({
                "sample_id": item["id"],
                "sample_code": item["sample_code"],
                "batch_id": item["batch_id"],
                "batch_code": item["batch_code"],
                "location_id": item["location_id"],
                "location_code": item["location_code"],
                "root_sample_id": item["root_sample_id"],
                "root_sample_code": item["root_sample_code"],
                "lifecycle_state": item["lifecycle_state"],
                "is_seed": item["id"] == seed_sample_id,
                "basis": reasons,
            })
        return candidates

    # ----------------------------------------------------------------- labels
    def _batch_label(self, batch_id: int) -> str | None:
        row = self.connection.execute("SELECT batch_code FROM receipt_batches WHERE id=?", (batch_id,)).fetchone()
        return row[0] if row else None

    def _location_label(self, location_id: int) -> str | None:
        row = self.connection.execute("SELECT code FROM storage_locations WHERE id=?", (location_id,)).fetchone()
        return row[0] if row else None

    def _sample_label(self, sample_id: int) -> str | None:
        row = self.connection.execute("SELECT sample_code FROM samples WHERE id=?", (sample_id,)).fetchone()
        return row[0] if row else None
