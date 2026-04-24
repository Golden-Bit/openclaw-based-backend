import asyncio
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core import knowledge_upload_tasks as knowledge_upload_tasks_module
from app.core.knowledge_upload_tasks import (
    KNOWLEDGE_UPLOAD_STAGE_DIRNAME,
    _cleanup_stage_dir,
    build_knowledge_upload_task_accepted_response,
    get_knowledge_file_task_info,
    stage_payload_for_knowledge_task,
)


class _FakeScalarResult:
    def __init__(self, tasks):
        self._tasks = tasks

    def all(self):
        return list(self._tasks)


class _FakeExecuteResult:
    def __init__(self, tasks):
        self._tasks = tasks

    def scalars(self):
        return _FakeScalarResult(self._tasks)


class _FakeAsyncSession:
    def __init__(self, tasks):
        self._tasks = tasks

    async def execute(self, _stmt):
        return _FakeExecuteResult(self._tasks)


def _result_payload(path: str, filename: str) -> dict:
    return {
        'ok': True,
        'agent_id': 'u1-main',
        'path': path,
        'filename': filename,
        'size_bytes': 8,
        'sha256': 'abc123',
        'mime_type': 'application/pdf' if filename.endswith('.pdf') else 'text/markdown',
        'updated_at': datetime.utcnow().isoformat(),
    }


def _task(
    *,
    status: str,
    requested_path: str | None = None,
    folder_path: str | None = None,
    filename: str | None = None,
    result_payload: dict | None = None,
    updated_seconds: int = 0,
):
    now = datetime.utcnow() + timedelta(seconds=updated_seconds)
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id='u1',
        agent_id='u1-main',
        workspace='/tmp/ws',
        source_kind='base64',
        folder_path=folder_path,
        requested_path=requested_path,
        filename=filename,
        mime_type='application/pdf' if (filename or '').endswith('.pdf') else 'text/markdown',
        overwrite=False,
        upsert=False,
        stage_dir='',
        staged_size_bytes=8,
        staged_sha256='abc123',
        status=status,
        result_payload=result_payload,
        error_detail=None,
        started_at=now if status in {'running', 'succeeded', 'failed', 'expired'} else None,
        finished_at=now if status in {'succeeded', 'failed', 'expired'} else None,
        expires_at=now + timedelta(minutes=30),
        created_at=now,
        updated_at=now,
    )


def test_stage_payload_for_knowledge_task_writes_hidden_workspace_file(tmp_path: Path):
    task_id = uuid.uuid4()
    payload_path = stage_payload_for_knowledge_task(str(tmp_path / 'ws'), task_id, b'hello background task')

    assert payload_path.name == 'payload.bin'
    assert payload_path.read_bytes() == b'hello background task'
    assert KNOWLEDGE_UPLOAD_STAGE_DIRNAME in payload_path.as_posix()



def test_cleanup_stage_dir_removes_staged_payload(tmp_path: Path):
    task_id = uuid.uuid4()
    payload_path = stage_payload_for_knowledge_task(str(tmp_path / 'ws'), task_id, b'data')

    _cleanup_stage_dir(str(payload_path.parent))

    assert not payload_path.parent.exists()



def test_build_knowledge_upload_task_accepted_response_uses_task_fields():
    task_id = uuid.uuid4()
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(minutes=30)
    task = SimpleNamespace(
        id=task_id,
        agent_id='u1-main',
        status='pending',
        created_at=created_at,
        expires_at=expires_at,
    )

    response = build_knowledge_upload_task_accepted_response(task)

    assert response.task_id == task_id
    assert response.agent_id == 'u1-main'
    assert response.status == 'pending'
    assert response.status_url.endswith(f'/api/v1/agents/u1-main/knowledge/tasks/{task_id}')



def test_get_knowledge_file_task_info_matches_latest_active_task(monkeypatch, tmp_path: Path):
    target = tmp_path / 'knowledge' / 'research' / 'brief.pdf'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'%PDF')

    expire_calls: list[dict] = []

    async def _expire(db, **kwargs):
        expire_calls.append(kwargs)
        return []

    monkeypatch.setattr(knowledge_upload_tasks_module, 'expire_stale_knowledge_upload_tasks', _expire)

    newest_running = _task(status='running', folder_path='research', filename='brief.pdf', updated_seconds=2)
    older_pending = _task(status='pending', requested_path='research/brief.pdf', filename='brief.pdf', updated_seconds=1)

    info = asyncio.run(
        get_knowledge_file_task_info(
            _FakeAsyncSession([newest_running, older_pending]),
            user_id='u1',
            agent_id='u1-main',
            file_rel='research/brief.pdf',
            target=target,
        )
    )

    assert expire_calls == [{'user_id': 'u1', 'agent_id': 'u1-main', 'include_running': True}]
    assert info.association_status == 'direct'
    assert info.canonical_path == 'research/brief.pdf'
    assert info.active_task is not None
    assert info.active_task.task_id == newest_running.id
    assert info.latest_successful_task is None



def test_get_knowledge_file_task_info_matches_success_by_result_path_after_rename(monkeypatch, tmp_path: Path):
    target = tmp_path / 'knowledge' / 'research' / 'brief-1.pdf'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'%PDF')

    async def _expire(_db, **_kwargs):
        return []

    monkeypatch.setattr(knowledge_upload_tasks_module, 'expire_stale_knowledge_upload_tasks', _expire)

    renamed_success = _task(
        status='succeeded',
        requested_path='research/brief.pdf',
        filename='brief.pdf',
        result_payload=_result_payload('research/brief-1.pdf', 'brief-1.pdf'),
        updated_seconds=2,
    )
    older_success = _task(
        status='succeeded',
        requested_path='research/brief.pdf',
        filename='brief.pdf',
        result_payload=_result_payload('research/brief.pdf', 'brief.pdf'),
        updated_seconds=1,
    )

    info = asyncio.run(
        get_knowledge_file_task_info(
            _FakeAsyncSession([renamed_success, older_success]),
            user_id='u1',
            agent_id='u1-main',
            file_rel='research/brief-1.pdf',
            target=target,
        )
    )

    assert info.association_status == 'direct'
    assert info.canonical_path == 'research/brief-1.pdf'
    assert info.active_task is None
    assert info.latest_successful_task is not None
    assert info.latest_successful_task.task_id == renamed_success.id
    assert info.latest_successful_task.result is not None
    assert info.latest_successful_task.result.path == 'research/brief-1.pdf'



def test_get_knowledge_file_task_info_uses_managed_original_for_markdown(monkeypatch, tmp_path: Path):
    folder = tmp_path / 'knowledge' / 'research'
    folder.mkdir(parents=True)
    original = folder / 'brief.pdf'
    original.write_bytes(b'%PDF')
    target = folder / 'brief.md'
    target.write_text('# Generated', encoding='utf-8')

    async def _expire(_db, **_kwargs):
        return []

    monkeypatch.setattr(knowledge_upload_tasks_module, 'expire_stale_knowledge_upload_tasks', _expire)

    running_original = _task(status='running', requested_path='research/brief.pdf', filename='brief.pdf', updated_seconds=2)
    success_original = _task(
        status='succeeded',
        requested_path='research/brief.pdf',
        filename='brief.pdf',
        result_payload=_result_payload('research/brief.pdf', 'brief.pdf'),
        updated_seconds=1,
    )

    info = asyncio.run(
        get_knowledge_file_task_info(
            _FakeAsyncSession([running_original, success_original]),
            user_id='u1',
            agent_id='u1-main',
            file_rel='research/brief.md',
            target=target,
        )
    )

    assert info.association_status == 'managed_original'
    assert info.canonical_path == 'research/brief.pdf'
    assert info.active_task is not None
    assert info.active_task.requested_path == 'research/brief.pdf'
    assert info.latest_successful_task is not None
    assert info.latest_successful_task.result is not None
    assert info.latest_successful_task.result.path == 'research/brief.pdf'
