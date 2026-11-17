"""Phase 4: package layout, compatibility of ``import app``, shared web/API logic."""
import ast
import os
import subprocess
import sys

import pytest
from flask import g

import gewichts_tracker
from app import BodyWeight, PlannedTraining, TrainingPlan, db

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, 'gewichts_tracker')
ORDER = [m.__name__.split('gewichts_tracker.', 1)[1] for m in gewichts_tracker.MODULES]


def _module_imports(name):
    path = os.path.join(PKG, *name.split('.')) + '.py'
    with open(path, encoding='utf-8') as handle:
        tree = ast.parse(handle.read())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('gewichts_tracker'):
            target = node.module[len('gewichts_tracker'):].lstrip('.')
            if target:
                found.add(target)
            else:
                found.update(alias.name for alias in node.names)
    return found


def test_lower_modules_never_import_higher_ones():
    for index, name in enumerate(ORDER):
        for target in _module_imports(name):
            assert target in ORDER, (name, target)
            assert ORDER.index(target) < index, f'{name} importiert {target}, das weiter oben in der Schichtung steht'


@pytest.mark.parametrize('name', ['core', 'models', 'security', 'services', 'forms', 'data_io', 'api', 'views.training'])
def test_module_imports_on_its_own(name, tmp_path):
    env = dict(os.environ, GEWICHTS_TRACKER_DATABASE_URI=f'sqlite:///{tmp_path / "x.db"}',
               GEWICHTS_TRACKER_NO_AUTO_MIGRATE='1', SECRET_KEY='structure-test-secret-0123456789')
    code = f'import importlib; importlib.import_module("gewichts_tracker.{name}")'
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_legacy_app_module_still_exposes_everything():
    import app
    for name in ('app', 'db', 'User', 'get_app_settings', 'sanitize_external_url', 'parse_training_plan_markdown',
                 'calculate_exercise_statistics', 'delete_user_with_data', 'migrate_legacy_photo_uploads',
                 '_get_fernet', 'LEGACY_UPLOAD_FOLDER', 'DEFAULT_CSP', 'limiter', 'login_required'):
        assert hasattr(app, name), name
    assert app.app.name == 'app'
    assert app.app.root_path == ROOT
    assert app.app.instance_path == os.path.join(ROOT, 'instance')
    assert app.LEGACY_UPLOAD_FOLDER == os.path.join(ROOT, 'static', 'uploads', 'photos')


def _login(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = user.get_id()
    g.pop('_login_user', None)


class TestApiNowValidatesLikeWeb:
    @pytest.mark.parametrize('weight', [5, 999, -1, 'viel', float('inf'), True, [80]])
    def test_body_weight_range(self, logged_in_client, regular_user, weight):
        payload = '{"weight": %s}' % ('Infinity' if weight == float('inf') else __import__('json').dumps(weight))
        resp = logged_in_client.post('/api/body_weight', data=payload, content_type='application/json')
        assert resp.status_code == 400
        assert BodyWeight.query.count() == 0

    def test_body_weight_ok(self, logged_in_client, regular_user):
        resp = logged_in_client.post('/api/body_weight', json={'weight': '81,5', 'notes': '  morgens '})
        assert resp.status_code == 201
        entry = BodyWeight.query.one()
        assert (entry.weight, entry.notes) == (81.5, 'morgens')

    @pytest.mark.parametrize('payload', [{'date': 20260101}, {'date': '2026-01-01', 'label': {'x': 1}}, {'date': ['2026-01-01']}])
    def test_calendar_rejects_bad_types(self, logged_in_client, regular_user, payload):
        assert logged_in_client.post('/api/calendar/plan', json=payload).status_code == 400
        assert PlannedTraining.query.count() == 0

    def test_calendar_label_is_trimmed(self, logged_in_client, regular_user):
        resp = logged_in_client.post('/api/calendar/plan', json={'date': '2026-01-01', 'label': '  ' + 'x' * 300})
        assert resp.status_code == 201
        assert PlannedTraining.query.one().label == 'x' * 100

    @pytest.mark.parametrize('payload', [{'exercise_id': 1, 'superset_group': 'A'}, {'exercise_id': '1', 'superset_group': 1},
                                         {'exercise_id': 1, 'superset_group': 99999}])
    def test_superset_rejects_bad_values(self, logged_in_client, sample_plan, payload):
        assert logged_in_client.post(f'/api/training_plans/{sample_plan.id}/set_superset', json=payload).status_code == 400

    def test_reorder_rejects_string_id(self, logged_in_client, sample_plan):
        resp = logged_in_client.post(f'/api/training_plans/{sample_plan.id}/reorder', json={'exercise_id': 'x', 'direction': 'up'})
        assert resp.status_code == 400

    def test_web_and_api_copy_plans_identically(self, app, sample_plan, admin_user):
        sample_plan.share_token = 'tok-struct'
        db.session.commit()
        web = app.test_client()
        _login(web, admin_user)
        web.post('/shared/tok-struct')
        api = app.test_client()
        _login(api, admin_user)
        api.post('/api/shared/tok-struct/copy')
        copies = TrainingPlan.query.filter_by(user_id=admin_user.id).order_by(TrainingPlan.id).all()
        assert len(copies) == 2
        describe = lambda plan: sorted((e.name, e.exercise_type, e.user_id) for e in plan.exercises)
        assert copies[0].title == copies[1].title == 'Testplan (kopiert)'
        assert describe(copies[0]) == describe(copies[1])
