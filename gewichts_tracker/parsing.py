"""Hilfsfunktionen zum Prüfen von Request-Daten."""

from flask import jsonify, request

from gewichts_tracker.core import _utcnow


def _get_json_payload():
    data = request.get_json(silent=True)
    if data is None:
        return None, jsonify({'error': 'valid JSON body required'}), 400
    if not isinstance(data, dict):
        return None, jsonify({'error': 'JSON body must be an object'}), 400
    return data, None, None


def _parse_int_field(value, field_name, *, minimum=None, maximum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f'{field_name} must be an integer')
    if minimum is not None and parsed < minimum:
        raise ValueError(f'{field_name} must be at least {minimum}')
    if maximum is not None and parsed > maximum:
        raise ValueError(f'{field_name} must be at most {maximum}')
    return parsed


def _parse_float_field(value, field_name, *, minimum=None, maximum=None):
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise ValueError(f'{field_name} must be a number')
    if minimum is not None and parsed < minimum:
        raise ValueError(f'{field_name} must be at least {minimum}')
    if maximum is not None and parsed > maximum:
        raise ValueError(f'{field_name} must be at most {maximum}')
    return parsed


def _parse_optional_body_weight(value):
    cleaned = (value or '').strip()
    if not cleaned:
        return None
    return _parse_float_field(cleaned, 'body_weight', minimum=20, maximum=500)


def _parse_calendar_month_args():
    year = request.args.get('year', _utcnow().year, type=int)
    month = request.args.get('month', _utcnow().month, type=int)
    if year is None or month is None:
        raise ValueError('year and month must be integers')
    if month < 1 or month > 12:
        raise ValueError('month must be between 1 and 12')
    return year, month
