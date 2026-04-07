"""Tests for dashboard, statistics, and achievements routes."""
import pytest


class TestDashboard:
    def test_dashboard_requires_login(self, client):
        resp = client.get('/dashboard')
        assert resp.status_code == 302

    def test_dashboard_loads(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/dashboard')
        assert resp.status_code == 200
        assert b'Dashboard' in resp.data

    def test_dashboard_empty(self, logged_in_client):
        resp = logged_in_client.get('/dashboard')
        assert resp.status_code == 200


class TestStatistics:
    def test_statistics_requires_login(self, client):
        resp = client.get('/statistics')
        assert resp.status_code == 302

    def test_statistics_loads(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/statistics')
        assert resp.status_code == 200

    def test_statistics_empty(self, logged_in_client):
        resp = logged_in_client.get('/statistics')
        assert resp.status_code == 200


class TestAchievements:
    def test_achievements_requires_login(self, client):
        resp = client.get('/achievements')
        assert resp.status_code == 302

    def test_achievements_loads(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/achievements')
        assert resp.status_code == 200
