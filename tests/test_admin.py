"""Tests for admin routes."""
import pytest
from app import db, User
from werkzeug.security import generate_password_hash


class TestAdminAccess:
    def test_admin_page_requires_admin(self, logged_in_client):
        resp = logged_in_client.get('/admin')
        assert resp.status_code == 403

    def test_admin_page_loads(self, admin_client):
        resp = admin_client.get('/admin')
        assert resp.status_code == 200

    def test_admin_settings_page(self, admin_client):
        resp = admin_client.get('/admin/settings')
        assert resp.status_code == 200

    def test_admin_settings_requires_admin(self, logged_in_client):
        resp = logged_in_client.get('/admin/settings')
        assert resp.status_code == 403


class TestUserManagement:
    def test_change_password(self, admin_client, regular_user):
        resp = admin_client.post(f'/admin/user/{regular_user.id}/change_password', data={
            'new_password': 'newpass123',
            'confirm_new_password': 'newpass123',
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_delete_user(self, admin_client, app):
        target = User(username='deleteme', password=generate_password_hash('x'))
        db.session.add(target)
        db.session.commit()
        tid = target.id
        resp = admin_client.post(f'/admin/user/{tid}/delete', follow_redirects=True)
        assert resp.status_code == 200
        assert db.session.get(User, tid) is None

    def test_set_trainer(self, admin_client, regular_user):
        resp = admin_client.post(f'/admin/user/{regular_user.id}/set_trainer', follow_redirects=True)
        assert resp.status_code == 200
        db.session.refresh(regular_user)
        assert regular_user.is_trainer is True

    def test_remove_trainer(self, admin_client, trainer_user):
        resp = admin_client.post(f'/admin/user/{trainer_user.id}/remove_trainer', follow_redirects=True)
        assert resp.status_code == 200
        db.session.refresh(trainer_user)
        assert trainer_user.is_trainer is False

    def test_regular_user_cannot_manage(self, logged_in_client, admin_user):
        resp = logged_in_client.post(f'/admin/user/{admin_user.id}/set_trainer')
        assert resp.status_code == 403


class TestFooterManagement:
    def test_footer_links_page(self, admin_client):
        resp = admin_client.get('/admin/footer_links')
        assert resp.status_code == 200

    def test_create_footer_link(self, admin_client):
        resp = admin_client.post('/admin/footer_links', data={
            'title': 'Impressum',
            'url': 'https://example.com',
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_footer_pages_page(self, admin_client):
        resp = admin_client.get('/admin/footer_pages')
        assert resp.status_code == 200

    def test_create_footer_page(self, admin_client):
        resp = admin_client.post('/admin/footer_pages', data={
            'title': 'Datenschutz',
            'content': 'Datenschutztext hier...',
        }, follow_redirects=True)
        assert resp.status_code == 200


class TestTemplatePlans:
    def test_template_plans_list(self, trainer_client):
        resp = trainer_client.get('/admin/template_plans')
        assert resp.status_code == 200

    def test_template_plans_requires_trainer(self, logged_in_client):
        resp = logged_in_client.get('/admin/template_plans')
        assert resp.status_code == 403

    def test_create_template_plan(self, trainer_client):
        resp = trainer_client.post('/admin/template_plan/create', data={
            'title': 'Anfänger Plan',
            'description': 'Für Einsteiger',
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_user_template_plans_list(self, logged_in_client):
        resp = logged_in_client.get('/template_plans')
        assert resp.status_code == 200
