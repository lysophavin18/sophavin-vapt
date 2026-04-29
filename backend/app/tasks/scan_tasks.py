"""Celery scan task stubs — actual execution is handled by the orchestrator container"""

import structlog

logger = structlog.get_logger()


class TaskStub:
    """Celery-like stub used by the API when the orchestrator owns execution."""

    def __init__(self, name: str):
        self.name = name

    def __call__(self, task_id: str):
        logger.info("%s called", self.name, task_id=task_id)

    def delay(self, task_id: str):
        logger.info("%s queued", self.name, task_id=task_id)


execute_scan = TaskStub("execute_scan")
execute_batch_scan = TaskStub("execute_batch_scan")
