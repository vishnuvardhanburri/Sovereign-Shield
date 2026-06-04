"""
Durable asynchronous job queue for AI-heavy request paths.

The queue stores job metadata in SQL so status/result/cancel requests work across
multiple Uvicorn worker processes. Worker threads claim queued rows atomically and
execute registered handlers outside the request-response path.
"""
import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from sqlalchemy.exc import OperationalError

try:
    from audit.ledger import audit_ledger
    from db.models import AsyncJob
    from db.session import SessionLocal
except ImportError:
    from .audit.ledger import audit_ledger
    from .db.models import AsyncJob
    from .db.session import SessionLocal


JobHandler = Callable[[Dict[str, Any], Dict[str, Any], Callable[[], bool]], Dict[str, Any]]


TERMINAL_STATUSES = {"succeeded", "failed", "cancelled", "timeout"}


def _utcnow():
    return datetime.now(timezone.utc)


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return json.loads(json.dumps(value, default=str))


def _exception_payload(exc: BaseException) -> Dict[str, Any]:
    detail = getattr(exc, "detail", None)
    return {
        "type": exc.__class__.__name__,
        "detail": detail if detail is not None else str(exc),
        "status_code": getattr(exc, "status_code", None),
    }


class AsyncJobQueue:
    def __init__(self):
        self._handlers: Dict[str, JobHandler] = {}
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._executor = self._new_executor()
        self._executor_closed = False
        self._poll_interval = float(os.getenv("ASYNC_JOB_POLL_INTERVAL_SECONDS", "0.15"))

    def _new_executor(self) -> ThreadPoolExecutor:
        return ThreadPoolExecutor(
            max_workers=max(1, int(os.getenv("ASYNC_JOB_EXECUTOR_THREADS", "4"))),
            thread_name_prefix="SovereignJobExecutor",
        )

    def register(self, job_type: str, handler: JobHandler) -> None:
        self._handlers[job_type] = handler

    def start(self) -> None:
        with self._lock:
            if any(thread.is_alive() for thread in self._threads):
                return
            if self._executor_closed:
                self._executor = self._new_executor()
                self._executor_closed = False
            self._stop_event.clear()
            worker_count = max(1, int(os.getenv("ASYNC_JOB_WORKERS_PER_PROCESS", "1")))
            self._threads = []
            for index in range(worker_count):
                thread = threading.Thread(
                    target=self._worker_loop,
                    name=f"SovereignAsyncJobWorker-{index + 1}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)

    def shutdown(self) -> None:
        self._stop_event.set()
        for thread in list(self._threads):
            thread.join(timeout=2)
        if not self._executor_closed:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor_closed = True

    def enqueue(
        self,
        job_type: str,
        payload: Dict[str, Any],
        actor: Dict[str, Any],
        timeout_seconds: Optional[int] = None,
        max_retries: Optional[int] = None,
    ) -> Dict[str, Any]:
        if job_type not in self._handlers:
            raise ValueError(f"Job handler not registered: {job_type}")

        self.start()
        timeout = int(timeout_seconds or os.getenv("AI_JOB_TIMEOUT_SECONDS", "90"))
        retries = int(max_retries if max_retries is not None else os.getenv("AI_JOB_MAX_RETRIES", "1"))
        now = _utcnow()
        job = AsyncJob(
            id=str(uuid.uuid4()),
            tenant_id=actor.get("tenant_id") or "default",
            user_id=actor.get("sub") or actor.get("email") or "UNKNOWN",
            user_role=actor.get("role") or "STAFF",
            department=actor.get("department"),
            job_type=job_type,
            status="queued",
            payload=_json_safe(payload or {}),
            attempts=0,
            max_retries=max(0, retries),
            timeout_seconds=max(1, timeout),
            cancel_requested=False,
            created_at=now,
            updated_at=now,
        )
        db = SessionLocal()
        try:
            db.add(job)
            db.commit()
            db.refresh(job)
            snapshot = self._snapshot(job, include_result=False)
        finally:
            db.close()

        self._audit("AI_JOB_ACCEPTED", snapshot, {"status": "queued"})
        return snapshot

    def get_job(self, job_id: str, include_result: bool = True) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            job = db.query(AsyncJob).filter(AsyncJob.id == job_id).first()
            if not job:
                return None
            return self._snapshot(job, include_result=include_result)
        finally:
            db.close()

    def cancel(self, job_id: str, actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            job = db.query(AsyncJob).filter(AsyncJob.id == job_id).first()
            if not job:
                return None
            if job.status not in TERMINAL_STATUSES:
                job.cancel_requested = True
                job.updated_at = _utcnow()
                if job.status == "queued":
                    job.status = "cancelled"
                    job.completed_at = job.updated_at
                elif job.status == "running":
                    job.status = "cancelling"
                db.commit()
                db.refresh(job)
            snapshot = self._snapshot(job, include_result=True)
        finally:
            db.close()

        self._audit(
            "AI_JOB_CANCEL_REQUESTED",
            snapshot,
            {"requested_by": actor.get("sub") or actor.get("email") or "UNKNOWN"},
        )
        return snapshot

    def acceptance_payload(self, job: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "job_id": job["job_id"],
            "job_type": job["job_type"],
            "status": job["status"],
            "accepted_at": job["created_at"],
            "status_url": f"/api/v2/jobs/{job['job_id']}/status",
            "result_url": f"/api/v2/jobs/{job['job_id']}/result",
            "cancel_url": f"/api/v2/jobs/{job['job_id']}/cancel",
        }

    def is_cancel_requested(self, job_id: str) -> bool:
        db = SessionLocal()
        try:
            job = db.query(AsyncJob).filter(AsyncJob.id == job_id).first()
            return bool(job and job.cancel_requested)
        finally:
            db.close()

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                job = self._claim_next_job()
                if not job:
                    time.sleep(self._poll_interval)
                    continue
                self._execute(job)
            except OperationalError:
                time.sleep(max(0.5, self._poll_interval))
            except Exception as exc:
                audit_ledger.log(
                    action="AI_JOB_WORKER_ERROR",
                    user_id="SYSTEM",
                    user_role="SUPER_ADMIN",
                    metadata=_exception_payload(exc),
                )
                time.sleep(max(0.5, self._poll_interval))

    def _claim_next_job(self) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            candidate = (
                db.query(AsyncJob)
                .filter(AsyncJob.status == "queued")
                .order_by(AsyncJob.created_at.asc())
                .first()
            )
            if not candidate:
                return None
            now = _utcnow()
            updated = (
                db.query(AsyncJob)
                .filter(AsyncJob.id == candidate.id, AsyncJob.status == "queued")
                .update({
                    "status": "running",
                    "attempts": (candidate.attempts or 0) + 1,
                    "started_at": now,
                    "updated_at": now,
                })
            )
            db.commit()
            if updated != 1:
                return None
            job = db.query(AsyncJob).filter(AsyncJob.id == candidate.id).first()
            return self._snapshot(job, include_result=True) if job else None
        finally:
            db.close()

    def _execute(self, job: Dict[str, Any]) -> None:
        if self.is_cancel_requested(job["job_id"]):
            self._mark_cancelled(job)
            return

        handler = self._handlers.get(job["job_type"])
        if not handler:
            self._mark_failed(job, {"type": "MissingHandler", "detail": job["job_type"]})
            return

        self._audit("AI_JOB_STARTED", job, {"attempt": job["attempts"]})
        future = self._executor.submit(
            handler,
            job.get("payload") or {},
            self._actor_from_job(job),
            lambda: self.is_cancel_requested(job["job_id"]),
        )
        try:
            result = future.result(timeout=int(job.get("timeout_seconds") or 90))
            if self.is_cancel_requested(job["job_id"]):
                self._mark_cancelled(job)
                return
            self._mark_succeeded(job, result)
        except TimeoutError as exc:
            future.cancel()
            self._mark_retry_or_terminal(job, _exception_payload(exc), terminal_status="timeout")
        except Exception as exc:
            self._mark_retry_or_terminal(job, _exception_payload(exc), terminal_status="failed")

    def _mark_retry_or_terminal(self, job: Dict[str, Any], error: Dict[str, Any], terminal_status: str) -> None:
        if self.is_cancel_requested(job["job_id"]):
            self._mark_cancelled(job)
            return
        if int(job.get("attempts") or 0) <= int(job.get("max_retries") or 0):
            self._mark_retry(job, error)
            return
        if terminal_status == "timeout":
            self._mark_timeout(job, error)
        else:
            self._mark_failed(job, error)

    def _mark_retry(self, job: Dict[str, Any], error: Dict[str, Any]) -> None:
        snapshot = self._update_job(
            job["job_id"],
            {
                "status": "queued",
                "error": _json_safe(error),
                "updated_at": _utcnow(),
            },
        )
        self._audit("AI_JOB_RETRY_SCHEDULED", snapshot or job, {"error": error})

    def _mark_succeeded(self, job: Dict[str, Any], result: Dict[str, Any]) -> None:
        now = _utcnow()
        snapshot = self._update_job(
            job["job_id"],
            {
                "status": "succeeded",
                "result": _json_safe(result or {}),
                "error": None,
                "completed_at": now,
                "updated_at": now,
            },
        )
        self._audit("AI_JOB_COMPLETED", snapshot or job, {"status": "succeeded"})

    def _mark_failed(self, job: Dict[str, Any], error: Dict[str, Any]) -> None:
        now = _utcnow()
        snapshot = self._update_job(
            job["job_id"],
            {
                "status": "failed",
                "error": _json_safe(error),
                "completed_at": now,
                "updated_at": now,
            },
        )
        self._audit("AI_JOB_FAILED", snapshot or job, {"error": error})

    def _mark_timeout(self, job: Dict[str, Any], error: Dict[str, Any]) -> None:
        now = _utcnow()
        snapshot = self._update_job(
            job["job_id"],
            {
                "status": "timeout",
                "error": _json_safe(error),
                "completed_at": now,
                "updated_at": now,
            },
        )
        self._audit("AI_JOB_TIMEOUT", snapshot or job, {"error": error})

    def _mark_cancelled(self, job: Dict[str, Any]) -> None:
        now = _utcnow()
        snapshot = self._update_job(
            job["job_id"],
            {
                "status": "cancelled",
                "cancel_requested": True,
                "completed_at": now,
                "updated_at": now,
            },
        )
        self._audit("AI_JOB_CANCELLED", snapshot or job, {"status": "cancelled"})

    def _update_job(self, job_id: str, values: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        db = SessionLocal()
        try:
            db.query(AsyncJob).filter(AsyncJob.id == job_id).update(values)
            db.commit()
            job = db.query(AsyncJob).filter(AsyncJob.id == job_id).first()
            return self._snapshot(job, include_result=True) if job else None
        finally:
            db.close()

    def _snapshot(self, job: AsyncJob, include_result: bool = True) -> Dict[str, Any]:
        snapshot = {
            "job_id": job.id,
            "tenant_id": job.tenant_id,
            "user_id": job.user_id,
            "user_role": job.user_role,
            "department": job.department,
            "job_type": job.job_type,
            "status": job.status,
            "attempts": job.attempts,
            "max_retries": job.max_retries,
            "timeout_seconds": job.timeout_seconds,
            "cancel_requested": bool(job.cancel_requested),
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "updated_at": job.updated_at.isoformat() if job.updated_at else None,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "payload": job.payload or {},
        }
        if include_result:
            snapshot["result"] = job.result
            snapshot["error"] = job.error
        return snapshot

    def _actor_from_job(self, job: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "sub": job.get("user_id"),
            "email": job.get("user_id"),
            "role": job.get("user_role"),
            "department": job.get("department"),
            "tenant_id": job.get("tenant_id") or "default",
            "force_password_change": False,
        }

    def _audit(self, action: str, job: Dict[str, Any], metadata: Dict[str, Any]) -> None:
        audit_ledger.log(
            action=action,
            user_id=job.get("user_id") or "UNKNOWN",
            user_role=job.get("user_role") or "STAFF",
            department=job.get("department"),
            tenant_id=job.get("tenant_id") or "default",
            metadata={
                "job_id": job.get("job_id"),
                "job_type": job.get("job_type"),
                "status": job.get("status"),
                **(metadata or {}),
            },
        )


async_job_queue = AsyncJobQueue()
