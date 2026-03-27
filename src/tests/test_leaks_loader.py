"""
Tests for LeaksLoader — проверяем новый формат API и offset-based paging.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# pycti не установлен локально — мокаем перед любым импортом main
import uuid as _uuid
from unittest.mock import MagicMock

def _gen_id(name, cls):
    return f"identity--{str(_uuid.uuid5(_uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7'), name + cls))}"

_pycti_mock = MagicMock()
_pycti_mock.Identity.generate_id = staticmethod(_gen_id)
_pycti_mock.get_config_variable = MagicMock(return_value=None)
sys.modules.setdefault("pycti", _pycti_mock)

import json
import unittest
from unittest.mock import MagicMock, patch, call

from passleak.LeaksLoader import LeaksLoader

CONF = {
    "baseurl": "https://api.passleak.example/",
    "apikey": "test-token",
    "contimeout": 5,
    "readtimeout": 10,
    "retry": 1,
}

DOMAINS_RESP = {
    "items": [
        {"id": "uuid-domain-1", "host": "example.com", "approved": True},
        {"id": "uuid-domain-2", "host": "nonapproved.com", "approved": False},
    ]
}

MONITORING_PAGE1 = {
    "items": [
        {
            "domain": "example.com",
            "email": "user1@example.com",
            "login": "",
            "password": "pass1",
            "source": "leaked_db_2024",
            "event_time": "2024-03-01T12:00:00",
            "is_new": True,
            "stealer_type": "lumma",
        },
        {
            "domain": "example.com",
            "email": "user2@example.com",
            "login": "",
            "password": "pass2",
            "source": "leaked_db_2024",
            "event_time": "2024-03-01T12:01:00",
            "is_new": True,
            "stealer_type": "redline",
        },
    ],
    "paging": {"offset": 0, "limit": 200, "has_more": False, "total": 2},
}


def make_response(data: dict, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = data
    r.text = json.dumps(data)
    return r


class TestLeaksLoaderConnection(unittest.TestCase):
    def _make_loader(self):
        loader = LeaksLoader(CONF)
        loader._session = MagicMock()
        loader._is_connected = True
        return loader

    def test_base_url_normalized(self):
        loader = LeaksLoader({**CONF, "baseurl": "https://api.passleak.example"})
        self.assertTrue(loader.base_url.endswith("/"))

    def test_connect_success(self):
        loader = LeaksLoader(CONF)
        with patch("requests.Session") as mock_session_cls:
            session = MagicMock()
            session.get.return_value = make_response(DOMAINS_RESP)
            mock_session_cls.return_value = session
            loader.init_connection()
        self.assertTrue(loader._is_connected)

    def test_connect_failure_raises(self):
        loader = LeaksLoader(CONF)
        with patch("requests.Session") as mock_session_cls:
            session = MagicMock()
            session.get.return_value = make_response({}, status=500)
            mock_session_cls.return_value = session
            with self.assertRaises(Exception, msg="Cannot connect"):
                loader.init_connection()


class TestLeaksLoaderDomains(unittest.TestCase):
    def _make_loader(self):
        loader = LeaksLoader(CONF)
        loader._session = MagicMock()
        loader._is_connected = True
        return loader

    def test_only_approved_domains(self):
        loader = self._make_loader()
        monitoring_resp = make_response({"items": [], "paging": {"has_more": False, "total": 0}})
        loader._session.get.side_effect = [
            make_response(DOMAINS_RESP),   # /domains
            monitoring_resp,               # /monitoring for example.com
            # nonapproved.com should NOT be queried
        ]
        result = loader.download_leaks_data({})
        # Должен быть вызван только 1 monitoring запрос (для approved домена)
        calls = loader._session.get.call_args_list
        monitoring_calls = [c for c in calls if "monitoring" in str(c)]
        self.assertEqual(len(monitoring_calls), 1)

    def test_no_approved_domains(self):
        loader = self._make_loader()
        no_approved = {"items": [{"id": "x", "host": "test.com", "approved": False}]}
        loader._session.get.return_value = make_response(no_approved)
        result = loader.download_leaks_data({})
        self.assertEqual(result, {})


class TestLeaksLoaderMonitoring(unittest.TestCase):
    def _make_loader(self):
        loader = LeaksLoader(CONF)
        loader._session = MagicMock()
        loader._is_connected = True
        return loader

    def test_first_run_no_state(self):
        loader = self._make_loader()
        loader._session.get.side_effect = [
            make_response(DOMAINS_RESP),
            make_response(MONITORING_PAGE1),
        ]
        result = loader.download_leaks_data({})
        self.assertIn("example.com", result)
        self.assertEqual(len(result["example.com"]["items"]), 2)
        self.assertEqual(result["example.com"]["new_offset"], 2)

    def test_state_offset_used(self):
        """При наличии state offset должен передаваться в запрос."""
        loader = self._make_loader()
        loader._session.get.side_effect = [
            make_response(DOMAINS_RESP),
            make_response(MONITORING_PAGE1),
        ]
        state = {"example.com": {"offset": 50}}
        loader.download_leaks_data(state)

        monitoring_call = loader._session.get.call_args_list[1]
        params = monitoring_call.kwargs.get("params") or monitoring_call.args[1] if len(monitoring_call.args) > 1 else monitoring_call.kwargs.get("params", {})
        # Проверяем что offset=50 передан
        call_str = str(monitoring_call)
        self.assertIn("50", call_str)

    def test_backward_compat_old_state(self):
        """Старый формат state (record_id строкой) → offset=0."""
        loader = self._make_loader()
        loader._session.get.side_effect = [
            make_response(DOMAINS_RESP),
            make_response(MONITORING_PAGE1),
        ]
        # Старый формат — строка вместо dict
        state = {"example.com": "old-record-id-123"}
        result = loader.download_leaks_data(state)
        self.assertIn("example.com", result)
        # offset должен стартовать с 0 (fallback)
        self.assertEqual(result["example.com"]["new_offset"], 2)

    def test_pagination_multiple_pages(self):
        """Должен пройти все страницы при has_more=True."""
        loader = self._make_loader()

        page1 = {
            "items": [{"email": f"u{i}@ex.com", "login": "", "password": "p", "source": "src",
                        "event_time": "2024-01-01T00:00:00", "is_new": True, "stealer_type": None}
                      for i in range(3)],
            "paging": {"offset": 0, "limit": 3, "has_more": True, "total": 5},
        }
        page2 = {
            "items": [{"email": f"u{i}@ex.com", "login": "", "password": "p", "source": "src",
                        "event_time": "2024-01-01T00:00:00", "is_new": True, "stealer_type": None}
                      for i in range(3, 5)],
            "paging": {"offset": 3, "limit": 3, "has_more": False, "total": 5},
        }
        loader._session.get.side_effect = [
            make_response(DOMAINS_RESP),
            make_response(page1),
            make_response(page2),
        ]
        result = loader.download_leaks_data({})
        self.assertEqual(len(result["example.com"]["items"]), 5)
        self.assertEqual(result["example.com"]["new_offset"], 5)

    def test_no_new_items(self):
        """Если событий нет — домен не попадает в результат."""
        loader = self._make_loader()
        empty = {"items": [], "paging": {"has_more": False, "total": 10}}
        loader._session.get.side_effect = [
            make_response(DOMAINS_RESP),
            make_response(empty),
        ]
        result = loader.download_leaks_data({"example.com": {"offset": 10}})
        self.assertNotIn("example.com", result)

    def test_monitoring_api_error_raises(self):
        loader = self._make_loader()
        loader._session.get.side_effect = [
            make_response(DOMAINS_RESP),
            make_response({}, status=403),
        ]
        with self.assertRaises(Exception):
            loader.download_leaks_data({})


class TestStixBundleCreation(unittest.TestCase):
    """Тесты создания STIX объектов в main.py."""

    def _make_connector(self):
        """Создаём PasslekLeaks с замоканым helper."""
        import importlib
        import main as main_module

        connector = main_module.PasslekLeaks.__new__(main_module.PasslekLeaks)
        connector.helper = MagicMock()
        connector.helper.log_info = lambda msg: None
        connector.helper.log_debug = lambda msg: None
        connector._state_dir = "/tmp"
        connector.interval = 86400
        connector._downloader_config = {}
        return connector

    def _make_domain_data(self, items):
        return {"example.com": {"items": items, "new_offset": len(items)}}

    def test_malware_object_created_for_stealer(self):
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "a@b.com", "login": "", "password": "p", "source": "src",
             "event_time": "2024-01-01T00:00:00", "stealer_type": "lumma"},
        ])
        bundles = connector._create_stix_bundles(leaks)
        flat = bundles[0]
        malware_objs = [o for o in flat if isinstance(o, m.stix2.v21.Malware)]
        self.assertEqual(len(malware_objs), 1)
        self.assertEqual(malware_objs[0].name, "lumma")
        self.assertEqual(malware_objs[0].malware_types, ["stealer"])
        self.assertTrue(malware_objs[0].is_family)

    def test_no_malware_when_stealer_type_none(self):
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "a@b.com", "login": "", "password": "p", "source": "src",
             "event_time": "2024-01-01T00:00:00", "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        malware_objs = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Malware)]
        self.assertEqual(len(malware_objs), 0)

    def test_malware_deduplicated_across_records(self):
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "a@b.com", "login": "", "password": "p1", "source": "src",
             "event_time": "2024-01-01T00:00:00", "stealer_type": "lumma"},
            {"email": "c@b.com", "login": "", "password": "p2", "source": "src",
             "event_time": "2024-01-01T00:01:00", "stealer_type": "lumma"},
        ])
        bundles = connector._create_stix_bundles(leaks)
        malware_objs = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Malware)]
        self.assertEqual(len(malware_objs), 1)

    def test_incident_grouped_by_source(self):
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "a@b.com", "login": "", "password": "p1", "source": "breach_A",
             "event_time": "2024-01-01T00:00:00", "stealer_type": None},
            {"email": "b@b.com", "login": "", "password": "p2", "source": "breach_A",
             "event_time": "2024-01-01T00:01:00", "stealer_type": None},
            {"email": "c@b.com", "login": "", "password": "p3", "source": "breach_B",
             "event_time": "2024-01-01T00:02:00", "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        incidents = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Incident)]
        self.assertEqual(len(incidents), 2)
        names = {i.name for i in incidents}
        self.assertIn("Credential leak [breach_A] for example.com", names)
        self.assertIn("Credential leak [breach_B] for example.com", names)

    def test_login_field_used_when_no_email(self):
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "", "login": "johndoe", "password": "secret", "source": "src",
             "event_time": "2024-01-01T00:00:00", "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        accounts = [o for o in bundles[0] if isinstance(o, m.stix2.v21.UserAccount)]
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0].user_id, "johndoe")

    def test_record_skipped_if_no_identity(self):
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "", "login": "", "password": "secret", "source": "src",
             "event_time": "2024-01-01T00:00:00", "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        accounts = [o for o in bundles[0] if isinstance(o, m.stix2.v21.UserAccount)]
        self.assertEqual(len(accounts), 0)

    def test_incident_malware_relationship_not_duplicated(self):
        import main as m
        connector = self._make_connector()
        # Два записи с одинаковым source и stealer — только одна связь incident→malware
        leaks = self._make_domain_data([
            {"email": "a@b.com", "login": "", "password": "p1", "source": "src",
             "event_time": "2024-01-01T00:00:00", "stealer_type": "stealc"},
            {"email": "b@b.com", "login": "", "password": "p2", "source": "src",
             "event_time": "2024-01-01T00:01:00", "stealer_type": "stealc"},
        ])
        bundles = connector._create_stix_bundles(leaks)
        incidents = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Incident)]
        malwares = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Malware)]
        rels = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Relationship)
                and o.source_ref == incidents[0].id and o.target_ref == malwares[0].id]
        self.assertEqual(len(rels), 1)


class TestNullFields(unittest.TestCase):
    """Тесты на null/отсутствующие поля в записях API."""

    def _make_connector(self):
        import main as m
        connector = m.PasslekLeaks.__new__(m.PasslekLeaks)
        connector.helper = MagicMock()
        connector.helper.log_info = lambda msg: None
        connector.helper.log_debug = lambda msg: None
        connector.interval = 86400
        return connector

    def _make_domain_data(self, items):
        return {"example.com": {"items": items, "new_offset": len(items)}}

    def test_all_null_fields(self):
        """Запись где все поля null — не падает, просто пропускается."""
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": None, "login": None, "password": None,
             "source": None, "event_time": None, "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        accounts = [o for o in bundles[0] if isinstance(o, m.stix2.v21.UserAccount)]
        self.assertEqual(len(accounts), 0)

    def test_null_password_does_not_crash(self):
        """Null password → пустая строка, запись обрабатывается."""
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "user@example.com", "login": None, "password": None,
             "source": "src", "event_time": "2024-01-01T00:00:00", "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        accounts = [o for o in bundles[0] if isinstance(o, m.stix2.v21.UserAccount)]
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0].credential, "")

    def test_invalid_event_time_fallback(self):
        """Невалидный event_time → fallback на utcnow(), не падает."""
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "user@example.com", "login": None, "password": "p",
             "source": "src", "event_time": "not-a-date", "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        incidents = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Incident)]
        self.assertEqual(len(incidents), 1)

    def test_missing_fields_entirely(self):
        """Запись вообще без ключей — не падает."""
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([{}])
        bundles = connector._create_stix_bundles(leaks)
        accounts = [o for o in bundles[0] if isinstance(o, m.stix2.v21.UserAccount)]
        self.assertEqual(len(accounts), 0)

    def test_null_source_grouped_as_unknown(self):
        """null source → группируется в один инцидент 'unknown'."""
        import main as m
        connector = self._make_connector()
        leaks = self._make_domain_data([
            {"email": "a@b.com", "login": None, "password": "p1",
             "source": None, "event_time": "2024-01-01T00:00:00", "stealer_type": None},
            {"email": "b@b.com", "login": None, "password": "p2",
             "source": None, "event_time": "2024-01-01T00:01:00", "stealer_type": None},
        ])
        bundles = connector._create_stix_bundles(leaks)
        incidents = [o for o in bundles[0] if isinstance(o, m.stix2.v21.Incident)]
        self.assertEqual(len(incidents), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
