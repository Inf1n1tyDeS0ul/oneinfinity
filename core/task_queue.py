"""
Async Task Queue — priority-based work queue with worker pool.

Usage:
    queue = TaskQueue(max_workers=8)
    await queue.start()

    task_id = await queue.submit(
        fn=run_nuclei,
        args=["target.com"],
        kwargs={"tags": "xss"},
        priority=TaskPriority.HIGH,
        label="nuclei-xss",
    )

    result = await queue.wait(task_id)
    await queue.stop()
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


class TaskPriority(IntEnum):
    CRITICAL = 0   # exploit confirmation — run first
    HIGH = 1       # active vuln scanning
    NORMAL = 2     # passive recon
    LOW = 3        # background / enrichment


class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    task_id: str
    label: str
    fn: Callable
    args: Tuple
    kwargs: Dict[str, Any]
    priority: TaskPriority
    submitted_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    status: str = TaskStatus.PENDING
    result: Any = None
    error: Optional[str] = None

    # Used by PriorityQueue — lower priority value = higher urgency
    def __lt__(self, other: "Task") -> bool:
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.submitted_at < other.submitted_at

    @property
    def elapsed(self) -> Optional[float]:
        if self.started_at is None:
            return None
        end = self.finished_at or time.time()
        return end - self.started_at


class TaskQueue:
    """
    Async priority queue with a ThreadPoolExecutor backend so blocking
    tool subprocesses do not stall the event loop.
    """

    def __init__(self, max_workers: int = 8) -> None:
        self._max_workers = max_workers
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._tasks: Dict[str, Task] = {}
        self._futures: Dict[str, asyncio.Future] = {}
        self._executor: Optional[ThreadPoolExecutor] = None
        self._worker_tasks: List[asyncio.Task] = []
        self._running = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        if self._running:
            return
        self._executor = ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="bounty")
        self._running = True
        for i in range(self._max_workers):
            t = asyncio.create_task(self._worker(i), name=f"tq-worker-{i}")
            self._worker_tasks.append(t)
        log.info("TaskQueue started — %d workers", self._max_workers)

    async def stop(self, wait: bool = True) -> None:
        self._running = False
        # Poison-pill each worker
        for _ in self._worker_tasks:
            await self._queue.put((TaskPriority.LOW, _PoisonPill()))
        if wait:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        if self._executor:
            self._executor.shutdown(wait=False)
        log.info("TaskQueue stopped")

    # ------------------------------------------------------------------ #
    #  Submit / Wait
    # ------------------------------------------------------------------ #

    async def submit(
        self,
        fn: Callable,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        label: str = "",
    ) -> str:
        task_id = uuid.uuid4().hex[:12]
        task = Task(
            task_id=task_id,
            label=label or fn.__name__,
            fn=fn,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
        )
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        async with self._lock:
            self._tasks[task_id] = task
            self._futures[task_id] = fut
        await self._queue.put((int(priority), task))
        log.debug("Submitted task %s [%s] priority=%s", task_id, task.label, priority.name)
        return task_id

    async def wait(self, task_id: str, timeout: Optional[float] = None) -> Any:
        """Block until task completes and return its result (or raise on error)."""
        fut = self._futures.get(task_id)
        if fut is None:
            raise KeyError(f"Unknown task_id: {task_id}")
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Task {task_id} did not complete within {timeout}s")

    async def wait_many(
        self, task_ids: List[str], timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """Wait for multiple tasks; returns {task_id: result_or_exception}."""
        results: Dict[str, Any] = {}
        coros = {tid: self.wait(tid, timeout) for tid in task_ids}
        done = await asyncio.gather(*coros.values(), return_exceptions=True)
        for tid, outcome in zip(coros.keys(), done):
            results[tid] = outcome
        return results

    async def submit_batch(
        self,
        jobs: List[Dict[str, Any]],
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> List[str]:
        """Submit multiple jobs and return their task IDs."""
        ids = []
        for job in jobs:
            tid = await self.submit(
                fn=job["fn"],
                args=job.get("args", ()),
                kwargs=job.get("kwargs", {}),
                priority=job.get("priority", priority),
                label=job.get("label", ""),
            )
            ids.append(tid)
        return ids

    # ------------------------------------------------------------------ #
    #  Status
    # ------------------------------------------------------------------ #

    def get_task(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)

    def list_tasks(
        self, status: Optional[str] = None
    ) -> List[Task]:
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        return tasks

    def stats(self) -> dict:
        all_tasks = list(self._tasks.values())
        by_status: Dict[str, int] = {}
        for t in all_tasks:
            by_status[t.status] = by_status.get(t.status, 0) + 1
        return {
            "total": len(all_tasks),
            "by_status": by_status,
            "queue_size": self._queue.qsize(),
            "workers": self._max_workers,
        }

    # ------------------------------------------------------------------ #
    #  Worker
    # ------------------------------------------------------------------ #

    async def _worker(self, worker_id: int) -> None:
        loop = asyncio.get_event_loop()
        while True:
            _, item = await self._queue.get()
            if isinstance(item, _PoisonPill):
                self._queue.task_done()
                break

            task: Task = item
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()
            log.debug("Worker %d starting task %s [%s]", worker_id, task.task_id, task.label)

            fut = self._futures.get(task.task_id)
            try:
                result = await loop.run_in_executor(
                    self._executor,
                    lambda t=task: t.fn(*t.args, **t.kwargs),
                )
                task.result = result
                task.status = TaskStatus.DONE
                if fut and not fut.done():
                    fut.set_result(result)
            except Exception as exc:
                task.error = str(exc)
                task.status = TaskStatus.FAILED
                log.error("Task %s [%s] failed: %s", task.task_id, task.label, exc)
                if fut and not fut.done():
                    fut.set_exception(exc)
            finally:
                task.finished_at = time.time()
                self._queue.task_done()


class _PoisonPill:
    """Sentinel to stop a worker."""
    def __lt__(self, other):
        return True


# ------------------------------------------------------------------ #
#  Convenience: run coroutine batch with concurrency limit
# ------------------------------------------------------------------ #

async def run_parallel(
    coros: list,
    concurrency: int = 8,
    return_exceptions: bool = True,
) -> list:
    """
    Run a list of coroutines with a semaphore-limited concurrency.
    """
    sem = asyncio.Semaphore(concurrency)

    async def guarded(coro):
        async with sem:
            return await coro

    return await asyncio.gather(
        *[guarded(c) for c in coros],
        return_exceptions=return_exceptions,
    )
