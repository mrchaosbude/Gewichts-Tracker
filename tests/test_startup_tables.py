import importlib
import sys

import pytest
from sqlalchemy import inspect


@pytest.fixture
def reset_app_module():
    """Ensure a fresh import of the app module for each test."""

    def ours(name):
        return name == 'app' or name == 'gewichts_tracker' or name.startswith('gewichts_tracker.')

    original = {name: mod for name, mod in sys.modules.items() if ours(name)}
    for name in original:
        sys.modules.pop(name)
    yield
    for name in [n for n in sys.modules if ours(n)]:
        sys.modules.pop(name)
    sys.modules.update(original)


def test_startup_creates_missing_tables(tmp_path, monkeypatch, reset_app_module):
    db_file = tmp_path / 'startup.db'
    database_uri = f'sqlite:///{db_file}'
    monkeypatch.setenv('GEWICHTS_TRACKER_DATABASE_URI', database_uri)

    app_module = importlib.import_module('app')

    with app_module.app.app_context():
        engine = app_module.db.engine
        existing_tables = set(inspect(engine).get_table_names())
        defined_tables = set(app_module.db.metadata.tables.keys())

    assert defined_tables.issubset(existing_tables)
    assert db_file.exists()
