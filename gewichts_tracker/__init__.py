"""Gewichts-Tracker als Paket.

Beim Import werden alle Module in fester Reihenfolge geladen; Routen, Hooks und
die API registrieren sich dabei an der gemeinsamen Flask-App aus ``core``.
``app.py`` im Projektverzeichnis bleibt der Einstiegspunkt (uwsgi: ``app:app``).

Aufbau (untere Module importieren nie obere):

    core            Flask-App, Konfiguration, db, csrf, limiter, login_manager, api_bp
    crypto          Verschlüsselung, Passwort-Fingerabdruck
    models          Datenbankmodelle
    security        Zwei-Faktor-Anmeldung, Reset-Tokens, URL-Prüfung
    schema          Tabellen anlegen, fehlende Spalten ergänzen
    parsing, photos, serializers, permissions, stats, markdown_import
    mail, accounts, forms, services, data_io
    hooks           before/after_request, Context-Processor, Login-Loader
    views.*         Web-Seiten
    api             REST-API
"""

import os

from gewichts_tracker import core  # noqa: F401  (erst die App, dann alles, was sich daran registriert)
from gewichts_tracker import (  # noqa: F401
    crypto,
    models,
    security,
    schema,
    parsing,
    photos,
    serializers,
    permissions,
    stats,
    markdown_import,
    mail,
    accounts,
    forms,
    services,
    data_io,
    hooks,
)
from gewichts_tracker.views import auth, account, overview, tracking, training, sync, admin, template_plans  # noqa: F401
from gewichts_tracker import api  # noqa: F401
from gewichts_tracker.core import app
from gewichts_tracker.photos import migrate_legacy_photo_uploads
from gewichts_tracker.schema import _ensure_database_setup_once

MODULES = [
    core, crypto, models, security, schema, parsing, photos, serializers, permissions, stats,
    markdown_import, mail, accounts, forms, services, data_io, hooks,
    auth, account, overview, tracking, training, sync, admin, template_plans, api,
]

_ensure_database_setup_once()
if not os.environ.get('GEWICHTS_TRACKER_NO_AUTO_MIGRATE'):  # update.py steuert das selbst
    try:
        migrate_legacy_photo_uploads()
    except Exception as exc:  # pragma: no cover - defensive logging
        app.logger.warning('Legacy photo migration failed: %s', exc)


@app.before_request
def _ensure_tables_before_request() -> None:
    """Ensure database tables exist before handling the first request."""
    _ensure_database_setup_once()


def legacy_namespace():
    """Alle Namen der Module, wie sie früher direkt in app.py standen (für ``import app``)."""
    import types
    names = {}
    for module in MODULES:
        for key, value in vars(module).items():
            if key.startswith('__') or isinstance(value, types.ModuleType):
                continue
            names.setdefault(key, value)
    names['app'] = app
    return names
