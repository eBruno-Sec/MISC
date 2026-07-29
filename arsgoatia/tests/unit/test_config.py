from __future__ import annotations

from packages.config import ArsGoatiaSettings, get_settings


def test_default_settings():
    s = ArsGoatiaSettings()
    assert s.api_port == 8000
    assert "5433" in s.database_url
    assert s.log_level == "INFO"
    assert s.ai_redact_secrets is True


def test_settings_singleton():
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_settings_env_prefix():
    assert ArsGoatiaSettings.model_config.get("env_prefix") == "ARSGOATIA_"
