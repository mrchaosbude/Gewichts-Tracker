"""Einstiegspunkt des Gewichts-Trackers.

Der Code liegt im Paket ``gewichts_tracker`` (siehe dessen ``__init__.py`` für den
Aufbau). Diese Datei bleibt, damit ``uwsgi`` (``module = app:app``), ``flask --app app``,
``python app.py`` und ältere Skripte (``from app import db, User ...``) unverändert laufen.
"""

import os

import gewichts_tracker

# Alle Namen, die früher hier definiert waren, weiterhin unter ``app.<name>`` anbieten.
globals().update(gewichts_tracker.legacy_namespace())

from gewichts_tracker.core import app, db  # noqa: E402  (ausdrücklich, damit Werkzeuge sie finden)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
