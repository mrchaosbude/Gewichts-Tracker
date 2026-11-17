"""Ablage und Auslieferung von Fortschrittsfotos."""

import os
import shutil
import uuid

from gewichts_tracker.core import ALLOWED_EXTENSIONS, app, LEGACY_UPLOAD_FOLDER, MAX_REQUEST_BYTES


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _detect_image_extension(header: bytes):
    """Return the real image type based on magic bytes, or None."""
    if header.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if header.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'webp'
    return None


def save_progress_photo_file(file, user_id):
    """Validate and store an uploaded photo. Returns the stored filename.

    Raises ValueError if the content is not a PNG/JPEG/WebP image.
    """
    header = file.stream.read(16)
    file.stream.seek(0)
    ext = _detect_image_extension(header)
    if ext is None:
        raise ValueError('Datei ist kein gültiges Bild (PNG, JPG, WebP).')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    filename = f'{int(user_id)}_{uuid.uuid4().hex}.{ext}'
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


def save_progress_photo_bytes(data: bytes, user_id):
    """Store image bytes (from an import). Returns the filename; ValueError if not an image."""
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError('Ein Foto ist größer als 10 MB.')
    ext = _detect_image_extension(data[:16])
    if ext is None:
        raise ValueError('Eine Fotodatei ist kein gültiges Bild (PNG, JPG, WebP).')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    filename = f'{int(user_id)}_{uuid.uuid4().hex}.{ext}'
    with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as handle:
        handle.write(data)
    return filename


def progress_photo_path(photo):
    """Absolute path of a stored photo (basename only, no traversal)."""
    return os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(photo.filename or ''))


def remove_progress_photo_file(photo):
    path = progress_photo_path(photo)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError as exc:  # pragma: no cover - defensive logging
        app.logger.warning('Could not remove photo %s: %s', path, exc)


def migrate_legacy_photo_uploads(legacy_folder=None, target_folder=None):
    """Move photos out of the publicly served static/ folder. Returns count moved."""
    legacy_folder = legacy_folder or LEGACY_UPLOAD_FOLDER
    target_folder = target_folder or app.config['UPLOAD_FOLDER']
    if not os.path.isdir(legacy_folder):
        return 0
    if os.path.abspath(legacy_folder) == os.path.abspath(target_folder):
        return 0
    moved = 0
    for name in os.listdir(legacy_folder):
        src = os.path.join(legacy_folder, name)
        if not os.path.isfile(src) or not allowed_file(name):
            continue
        dst = os.path.join(target_folder, name)
        try:
            os.makedirs(target_folder, exist_ok=True)
            if not os.path.exists(dst):
                shutil.move(src, dst)
                moved += 1
        except OSError as exc:  # pragma: no cover - defensive logging
            app.logger.warning('Could not move legacy photo %s: %s', src, exc)
    if moved:
        app.logger.warning('Moved %d progress photo(s) from %s to private folder %s', moved, legacy_folder, target_folder)
    return moved
