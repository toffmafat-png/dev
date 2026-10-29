from __future__ import annotations

from dataclasses import replace

from fastapi.testclient import TestClient

from nova.main import create_app
from nova.provider import OpenAICompatibleProvider
from tests.conftest import FakeProvider, msg


def test_health_missing_credentials_and_tool_registry(environment):
    settings, db, registry, _workspace = environment
    settings = replace(settings, ai_api_key="")
    app = create_app(settings, provider=OpenAICompatibleProvider(settings), db=db, tools=registry)
    with TestClient(app) as client:
        health = client.get('/api/health')
        assert health.status_code == 200
        assert health.json()['provider_configured'] is False
        assert 'AI_API_KEY' not in str(health.json())
        chat = client.post('/api/chat', json={'message': 'Hello'})
        assert chat.status_code == 503
        assert 'Set AI_API_KEY' in chat.json()['detail']
        tools = client.get('/api/tools').json()['tools']
        assert any(tool['name'] == 'workspace.read_file' and tool['available'] for tool in tools)
        search = next(tool for tool in tools if tool['name'] == 'research.search_web')
        assert search['available'] is False


def test_goals_api_requires_configuration_and_manual_runs_create_auditable_tasks(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Review this configured objective","steps":["Check the requested scope","Report status"]}'),
        msg('The configured goal was reviewed. No external changes were made.'),
    ])
    app = create_app(settings, provider=provider, db=db, tools=registry)
    with TestClient(app) as client:
        created = client.post('/api/goals', json={
            'name': 'Daily study review',
            'objective': 'Review my study notes in the approved workspace and summarize open questions.',
            'interval_minutes': 1440,
        })
        assert created.status_code == 201, created.text
        goal = created.json()['goal']
        assert goal['enabled'] is False
        assert goal['cadence'] == 'Daily'
        assert client.get('/api/goals').json()['scheduler']['execution'].startswith('in-process only')
        unsafe = client.put(f"/api/goals/{goal['id']}", json={'enabled': True})
        assert unsafe.status_code == 200
        updated = client.get('/api/goals').json()['goals'][0]
        assert updated['enabled'] is True
        run = client.post(f"/api/goals/{goal['id']}/run")
        assert run.status_code == 202, run.text
        task_id = run.json()['task']['id']
        assert run.json()['task']['origin']['type'] == 'goal_manual'
        import time
        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] in {'completed', 'failed'}:
                break
            time.sleep(0.03)
        assert task['state'] == 'completed', task
        assert 'study notes' in task['objective']


def test_autonomy_policy_api_persists_controls_and_rejects_unsafe_scopes(environment):
    settings, db, registry, _workspace = environment
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as client:
        initial = client.get('/api/autonomy')
        assert initial.status_code == 200
        assert initial.json()['policy']['level'] == 'routine'
        updated = client.put('/api/autonomy', json={
            'level': 'advanced',
            'tool_overrides': {'math.calculate': 'approve'},
            'authorized_overwrite_prefixes': ['drafts'],
        })
        assert updated.status_code == 200, updated.text
        restored = client.get('/api/autonomy').json()['policy']
        assert restored['level'] == 'advanced'
        assert restored['tool_overrides'] == {'math.calculate': 'approve'}
        assert restored['authorized_overwrite_prefixes'] == ['drafts']
        assert 'do not add capabilities' in restored['notice']
        benchmark = client.post('/api/autonomy/benchmark')
        assert benchmark.status_code == 200, benchmark.text
        result = benchmark.json()
        assert result['suite'] == 'nova-autonomy-policy-v1'
        assert result['status'] == 'passed'
        assert result['passed'] == result['total'] == 7
        assert result['provider_requests'] == result['external_requests'] == 0
        assert result['isolated_temporary_workspace'] is True
        unsafe = client.put('/api/autonomy', json={
            'level': 'high', 'tool_overrides': {}, 'authorized_overwrite_prefixes': ['../outside'],
        })
        assert unsafe.status_code == 422


def test_setup_checklist_is_read_only_and_never_returns_provider_secrets(environment):
    settings, db, registry, _workspace = environment
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as client:
        response = client.get('/api/setup')
        assert response.status_code == 200
        payload = response.json()
        assert payload['secrets_exposed'] is False
        assert {item['id'] for item in payload['checks']} >= {'storage', 'workspace', 'provider', 'autonomy', 'scheduler'}
        assert 'test-only-not-a-real-key' not in str(payload)
        assert 'test-only-not-a-real-key' not in response.text


def test_auth_gate_and_http_only_session_cookie(environment):
    settings, db, registry, _workspace = environment
    settings = replace(settings, access_token='unit-test-access-token')
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as client:
        assert client.get('/api/auth/status').json() == {'required': True, 'authenticated': False}
        assert client.get('/api/tools').status_code == 401
        bad = client.post('/api/auth/login', json={'token': 'wrong'})
        assert bad.status_code == 401
        good = client.post('/api/auth/login', json={'token': 'unit-test-access-token'})
        assert good.status_code == 200
        cookie = good.headers.get('set-cookie', '')
        assert 'HttpOnly' in cookie
        assert client.get('/api/tools').status_code == 200
        client.post('/api/auth/logout')
        assert client.get('/api/tools').status_code == 401


def test_conversation_persists_with_provider_response(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([msg('Hello from the configured NOVA provider.')])
    app = create_app(settings, provider=provider, db=db, tools=registry)
    with TestClient(app) as client:
        response = client.post('/api/chat', json={'message': 'Hello, NOVA'})
        assert response.status_code == 200
        body = response.json()
        assert body['message']['content'] == 'Hello from the configured NOVA provider.'
        history = client.get(f"/api/conversations/{body['conversation_id']}/messages").json()['messages']
        assert [item['role'] for item in history] == ['user', 'assistant']


def test_model_registry_routes_use_secret_references_and_allow_disable(environment):
    settings, db, registry, _workspace = environment
    app = create_app(settings, provider=FakeProvider([]), db=db, tools=registry)
    with TestClient(app) as client:
        providers = client.get('/api/models/providers').json()['providers']
        assert {item['id'] for item in providers} >= {'openai_compatible', 'anthropic', 'gemini', 'deepseek', 'mistral', 'xai'}
        created = client.post('/api/models', json={
            'name': 'API Test Model', 'provider_type': 'anthropic',
            'base_url': 'https://api.anthropic.com/v1', 'model_id': 'account-visible-model',
            'api_key_env': 'ANTHROPIC_API_KEY', 'capabilities': ['chat'], 'is_default': True,
        })
        assert created.status_code == 201, created.text
        profile = created.json()['model']
        assert profile['configured'] is True  # the injected test adapter is a configured fake
        assert 'api_key' not in profile and 'secret' not in str(profile)
        profile_id = profile['id']
        updated = client.put(f'/api/models/{profile_id}', json={'enabled': False})
        assert updated.status_code == 200
        assert updated.json()['model']['status'] == 'disabled'
        raw_key = client.post('/api/models', json={
            'name': 'Invalid key field', 'provider_type': 'openai_compatible',
            'base_url': 'https://provider.example/v1', 'model_id': 'dynamic-id',
            'api_key_env': 'AI_API_KEY', 'api_key': 'should-not-be-accepted',
        })
        assert raw_key.status_code == 422


def test_chat_reports_selected_mode_and_actual_model_usage(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([msg('Balanced answer.')])
    app = create_app(settings, provider=provider, db=db, tools=registry)
    with TestClient(app) as client:
        response = client.post('/api/chat', json={'message': 'Hello', 'intelligence_mode': 'fast'})
        assert response.status_code == 200, response.text
        intelligence = response.json()['intelligence']
        assert intelligence['mode_requested'] == 'fast'
        assert intelligence['provider_requests'] == 1
        assert intelligence['models'][0]['status'] == 'ok'
        assert intelligence['usage_complete'] is True
        assert intelligence['run_id']
        usage = client.get('/api/usage').json()
        assert usage['usage_reported_complete'] is True


def test_chat_failure_reports_actual_provider_attempts(environment):
    settings, db, registry, _workspace = environment

    class Fails:
        async def chat(self, messages, tools=None):
            from nova.provider import ProviderError
            raise ProviderError("simulated provider outage", retryable=True)

    app = create_app(settings, provider=Fails(), db=db, tools=registry)
    with TestClient(app) as client:
        response = client.post('/api/chat', json={'message': 'Exercise a provider outage'})
        assert response.status_code == 502
        detail = response.json()['detail']
        assert detail['provider_requests'] == 1
        assert detail['models'][0]['status'] == 'failed'
        assert 'simulated provider outage' in detail['models'][0]['error']


def test_task_failure_records_actual_provider_attempts(environment):
    settings, db, registry, _workspace = environment

    class Fails:
        async def chat(self, messages, tools=None):
            from nova.provider import ProviderError
            raise ProviderError("simulated provider outage", retryable=True)

    app = create_app(settings, provider=Fails(), db=db, tools=registry)
    with TestClient(app) as client:
        created = client.post('/api/tasks', json={'objective': 'Exercise a bounded provider outage'})
        assert created.status_code == 202
        task_id = created.json()['id']
        import time
        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] in {'completed', 'failed'}:
                break
            time.sleep(0.03)
        assert task['state'] == 'failed'
        assert task['request_count'] == 1
        assert task['models_used']
        assert task['models_used'][0]['status'] == 'failed'
        assert task['usage_complete'] is False


def test_api_plan_review_edit_and_approval_gate(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Initial outline","steps":["Read the request"]}'),
        msg('The revised approved plan is complete.'),
    ])
    app = create_app(settings, provider=provider, db=db, tools=registry)
    with TestClient(app) as client:
        created = client.post('/api/tasks', json={'objective': 'Review and execute a simple plan', 'review_plan': True})
        assert created.status_code == 202
        task_id = created.json()['id']
        import time
        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] == 'waiting_approval':
                break
            time.sleep(0.03)
        assert task['state'] == 'waiting_approval'
        revised = client.put(f'/api/tasks/{task_id}/plan', json={'summary': 'User revised', 'steps': ['Check scope', 'Finish safely']})
        assert revised.status_code == 200
        approved = client.post(f'/api/tasks/{task_id}/approve', json={'approved': True})
        assert approved.status_code == 200
        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] in {'completed', 'failed'}:
                break
            time.sleep(0.03)
        assert task['state'] == 'completed', task
        assert task['plan']['summary'] == 'User revised'


def test_assisted_level_requires_plan_review_and_explicit_tool_approval(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Calculate carefully","steps":["Check the arithmetic","Report the result"]}'),
        msg(None, [{"id": "assisted-call", "type": "function", "function": {"name": "math.calculate", "arguments": '{"expression":"6 * 7"}'}}]),
        msg('The calculator returned 42.'),
        msg('{"status":"verified","note":"The calculation tool result supports 42."}'),
    ])
    app = create_app(settings, provider=provider, db=db, tools=registry)
    with TestClient(app) as client:
        changed = client.put('/api/autonomy', json={
            'level': 'assisted', 'tool_overrides': {}, 'authorized_overwrite_prefixes': [],
        })
        assert changed.status_code == 200
        created = client.post('/api/tasks', json={'objective': 'Calculate 6 times 7'})
        assert created.status_code == 202
        task_id = created.json()['id']
        import time
        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] == 'waiting_approval':
                break
            time.sleep(0.03)
        assert task['pending_approval']['kind'] == 'plan_review'
        assert client.post(f'/api/tasks/{task_id}/approve', json={'approved': True}).status_code == 200

        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] == 'waiting_approval' and task.get('pending_approval', {}).get('kind') == 'tool':
                break
            time.sleep(0.03)
        assert task['state'] == 'waiting_approval', task
        assert task['pending_approval']['tool'] == 'math.calculate'
        assert task['pending_approval']['approval']['policy_level'] == 'assisted'
        assert client.post(f'/api/tasks/{task_id}/approve', json={'approved': True}).status_code == 200

        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] in {'completed', 'failed'}:
                break
            time.sleep(0.03)
        assert task['state'] == 'completed', task
        assert task['autonomy_level'] == 'assisted'
        assert any(event['kind'] == 'autonomy_decision' for event in task['events'])


def test_task_api_runs_plan_tool_and_verified_result(environment):
    settings, db, registry, _workspace = environment
    provider = FakeProvider([
        msg('{"summary":"Calculate the result","steps":["Use the calculator","Report evidence"]}'),
        msg(None, [{"id": "api-call-1", "type": "function", "function": {"name": "math.calculate", "arguments": '{"expression":"6 * 7"}'}}]),
        msg('The safe calculator returned 42.'),
        msg('{"status":"verified","note":"The calculator evidence supports the result."}'),
    ])
    app = create_app(settings, provider=provider, db=db, tools=registry)
    with TestClient(app) as client:
        created = client.post('/api/tasks', json={'objective': 'Calculate 6 times 7'})
        assert created.status_code == 202
        task_id = created.json()['id']
        # The in-process task runner normally finishes before this first read. If it
        # has not, wait briefly for the event loop-backed background task to finish.
        import time
        deadline = time.time() + 3
        while time.time() < deadline:
            task = client.get(f'/api/tasks/{task_id}').json()
            if task['state'] in {'completed', 'failed'}:
                break
            time.sleep(0.03)
        assert task['state'] == 'completed', task
        assert task['verification'] == 'verified'
        assert '42' in task['result']
        assert any(event['kind'] == 'tool_result' for event in task['events'])
