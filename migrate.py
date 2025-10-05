#!/usr/bin/env python3
"""Simple database migration utility for Gewichts-Tracker.

This script ensures that legacy installations receive the ownership columns
introduced in newer releases and attempts to backfill the necessary data so
existing users retain access to their exercises and logged sessions.

Example usage::

    python migrate.py
    python migrate.py --database-uri sqlite:////path/to/fitness.db
    python migrate.py --dry-run --verbose
"""

from __future__ import annotations

import argparse
import logging
from contextlib import contextmanager
from typing import Iterable, Set

from sqlalchemy import inspect, text

from app import app, db, Exercise, ExerciseSession

LOGGER = logging.getLogger(__name__)


@contextmanager
def application_context(database_uri: str | None):
    """Provide an application context with an optional database override."""

    if database_uri:
        app.config["SQLALCHEMY_DATABASE_URI"] = database_uri
    with app.app_context():
        yield


def add_column_if_missing(table_name: str, column_name: str, ddl: str) -> bool:
    """Add a column to *table_name* when it does not yet exist."""

    engine = db.engine
    inspector = inspect(engine)
    columns = {col["name"] for col in inspector.get_columns(table_name)}
    if column_name in columns:
        LOGGER.debug("Column %s.%s already present", table_name, column_name)
        return False

    LOGGER.info("Adding column %s.%s", table_name, column_name)
    with engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}"))
    return True


def _plan_owner_ids(exercise) -> Set[int]:
    return {plan.user_id for plan in exercise.training_plans if plan.user_id is not None}


def backfill_exercise_owners() -> int:
    """Populate exercise.user_id where it can be determined unambiguously."""

    updates = 0
    for exercise in Exercise.query.all():
        owners = _plan_owner_ids(exercise)
        if len(owners) == 1:
            owner_id = next(iter(owners))
            if exercise.user_id != owner_id:
                LOGGER.debug("Assigning exercise %s to user %s", exercise.id, owner_id)
                exercise.user_id = owner_id
                updates += 1
        elif not owners:
            LOGGER.debug("Exercise %s has no plans attached; skipping", exercise.id)
        else:
            LOGGER.warning(
                "Exercise %s is linked to plans from multiple users (%s); manual review recommended",
                exercise.id,
                sorted(owners),
            )
    return updates


def backfill_session_owners() -> int:
    """Populate exercise_session.user_id where possible."""

    updates = 0
    for session in ExerciseSession.query.all():
        if session.user_id is not None:
            continue
        exercise = session.exercise
        if exercise is None:
            LOGGER.warning("Session %s references missing exercise; skipping", session.id)
            continue
        owners = _plan_owner_ids(exercise)
        chosen_user = None
        if len(owners) == 1:
            chosen_user = next(iter(owners))
        elif exercise.user_id is not None:
            chosen_user = exercise.user_id
        if chosen_user is not None:
            LOGGER.debug("Assigning session %s to user %s", session.id, chosen_user)
            session.user_id = chosen_user
            updates += 1
        else:
            LOGGER.warning(
                "Could not determine owner for session %s (exercise %s); leaving unset",
                session.id,
                exercise.id if exercise else "?",
            )
    return updates


def run_migration(database_uri: str | None, dry_run: bool) -> None:
    with application_context(database_uri):
        LOGGER.info("Running migrations")
        altered = False
        altered |= add_column_if_missing("exercise", "user_id", "INTEGER")
        altered |= add_column_if_missing("exercise_session", "user_id", "INTEGER")

        # Backfill ownership information so that historical data stays accessible.
        exercise_updates = backfill_exercise_owners()
        session_updates = backfill_session_owners()

        LOGGER.info(
            "Backfill summary: %s exercise ownership assignments, %s session ownership assignments",
            exercise_updates,
            session_updates,
        )

        if dry_run:
            db.session.rollback()
            LOGGER.info("Dry run complete; no changes committed")
        else:
            db.session.commit()
            LOGGER.info(
                "Migration finished successfully%s",
                " (schema altered)" if altered else "",
            )


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run database migrations for Gewichts-Tracker")
    parser.add_argument(
        "--database-uri",
        dest="database_uri",
        help="SQLAlchemy database URI. Defaults to the application's configured database.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform the migration without committing data changes.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output.",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    run_migration(args.database_uri, args.dry_run)


if __name__ == "__main__":
    main()
