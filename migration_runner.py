#!/usr/bin/env python3
"""Unified migration runner for Gewichts-Tracker.

Runs all pending migrations in order, tracks applied migrations in a
``schema_version`` table, and supports dry-run via database copy.

Usage::

    python migration_runner.py                  # run pending migrations
    python migration_runner.py --verbose        # with detailed output
    python migration_runner.py --mark-applied   # mark all as applied without running
    python migration_runner.py --dry-run        # run on a temporary copy
"""

from __future__ import annotations

import argparse
import importlib
import logging
import os
import shutil
import sys
import tempfile

from migration_utils import (
    MIGRATIONS,
    ensure_schema_version_table,
    get_applied_migrations,
    record_migration,
    resolve_db_path,
)

LOGGER = logging.getLogger(__name__)


def _run_single(migration_name: str, module_name: str, db_path: str) -> None:
    """Import *module_name* and call its ``migrate()`` function."""
    if module_name == 'migrate':
        # migrate.py uses SQLAlchemy; call run_migration() with a sqlite URI
        mod = importlib.import_module(module_name)
        uri = f'sqlite:///{db_path}'
        mod.run_migration(database_uri=uri, dry_run=False)
    else:
        mod = importlib.import_module(module_name)
        mod.migrate(db_path=db_path)


def run_all(
    db_path: str,
    *,
    mark_applied: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
) -> None:
    """Run (or mark) all pending migrations."""

    actual_path = db_path
    tmp_dir = None

    if dry_run:
        if not os.path.exists(db_path):
            LOGGER.error("Database %s does not exist; nothing to dry-run.", db_path)
            return
        tmp_dir = tempfile.mkdtemp(prefix='gewichts_dryrun_')
        tmp_path = os.path.join(tmp_dir, os.path.basename(db_path))
        shutil.copy2(db_path, tmp_path)
        actual_path = tmp_path
        LOGGER.info("Dry-run: working on temporary copy %s", tmp_path)

    try:
        ensure_schema_version_table(actual_path)
        applied = get_applied_migrations(actual_path)

        pending = [(name, mod) for name, mod in MIGRATIONS if name not in applied]

        if not pending:
            LOGGER.info("All migrations already applied.")
            return

        for name, module_name in pending:
            if mark_applied:
                LOGGER.info("Marking as applied: %s", name)
                record_migration(actual_path, name)
                continue

            LOGGER.info("Running migration: %s", name)
            try:
                _run_single(name, module_name, actual_path)
                record_migration(actual_path, name)
                LOGGER.info("  OK: %s", name)
            except Exception:
                LOGGER.exception("  FAILED: %s", name)
                LOGGER.error("Stopping migration runner. Fix the issue and re-run.")
                sys.exit(1)

        if dry_run:
            LOGGER.info("Dry-run complete. Original database was NOT modified.")
        elif mark_applied:
            LOGGER.info("All pending migrations marked as applied.")
        else:
            LOGGER.info("All migrations applied successfully.")
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run all pending database migrations for Gewichts-Tracker."
    )
    parser.add_argument(
        '--mark-applied',
        action='store_true',
        help='Mark all pending migrations as applied without running them.',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run migrations on a temporary copy of the database.',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging output.',
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(levelname)s: %(message)s',
    )
    db_path = resolve_db_path()
    LOGGER.info("Database: %s", db_path)
    run_all(
        db_path,
        mark_applied=args.mark_applied,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )


if __name__ == '__main__':
    main()
