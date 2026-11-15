"""Minimal .env support (no extra dependency).

``load_env_file()`` is called by app.py before the configuration is read, so
values written by ``update.py`` (e.g. SECRET_KEY) are picked up automatically.
Real environment variables always win over the file.
"""

from __future__ import annotations

import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ENV_PATH = os.path.join(APP_DIR, '.env')


def parse_env_file(path: str = DEFAULT_ENV_PATH) -> dict:
    """Return KEY -> value from a simple ``KEY=value`` file (missing file -> {})."""
    values = {}
    try:
        with open(path, encoding='utf-8') as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                if line.startswith('export '):
                    line = line[len('export '):].lstrip()
                key, value = line.split('=', 1)
                key, value = key.strip(), value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if key:
                    values[key] = value
    except FileNotFoundError:
        pass
    return values


def load_env_file(path: str = DEFAULT_ENV_PATH) -> dict:
    """Put values from the file into os.environ unless already set there."""
    values = parse_env_file(path)
    for key, value in values.items():
        os.environ.setdefault(key, value)
    return values


def update_env_file(values: dict, path: str = DEFAULT_ENV_PATH) -> None:
    """Set/replace keys in the file, keeping all other lines untouched."""
    lines = []
    try:
        with open(path, encoding='utf-8') as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        pass
    remaining = dict(values)
    out = []
    for line in lines:
        stripped = line.strip()
        key = stripped.split('=', 1)[0].replace('export ', '').strip() if '=' in stripped else None
        if key in remaining and not stripped.startswith('#'):
            out.append(f'{key}={remaining.pop(key)}')
        else:
            out.append(line)
    for key, value in remaining.items():
        out.append(f'{key}={value}')
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write('\n'.join(out) + '\n')
    try:
        os.chmod(path, 0o600)  # contains secrets
    except OSError:
        pass
