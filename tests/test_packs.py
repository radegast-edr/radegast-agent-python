"""Tests for the pack syncer."""

import io
import json
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent.packs import PackSyncer


def make_zip(files: dict[str, str]) -> bytes:
    """Create a zip file in memory with the given path→content mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, content in files.items():
            zf.writestr(path, content)
    return buf.getvalue()


@pytest.fixture
def setup_syncer():
    with tempfile.TemporaryDirectory() as tmpdir:
        rules_dir = Path(tmpdir) / "rules"
        rules_dir.mkdir()
        state_dir = Path(tmpdir) / "state"
        state_dir.mkdir()

        client = MagicMock()
        syncer = PackSyncer(client, rules_dir, state_dir)
        yield syncer, client, rules_dir, state_dir


class TestPackSync:
    def test_downloads_new_pack(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_name": "threat-intel",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]

        zip_data = make_zip({
            "sigma/detect_mimikatz.yml": "title: Mimikatz\n",
            "yara/malware.yar": "rule test { condition: true }",
            "ioc/hashes.txt": "abc123;test hash\n",
        })
        client.download_pack.return_value = zip_data

        updated = syncer.sync()
        assert updated == 1

        # Verify extraction
        assert (rules_dir / "sigma" / "threat-intel" / "detect_mimikatz.yml").exists()
        assert (rules_dir / "yara" / "threat-intel" / "malware.yar").exists()
        assert (rules_dir / "ioc" / "hashes.txt").exists()

    def test_skips_already_installed(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_name": "pack1",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]

        zip_data = make_zip({"sigma/rule.yml": "title: Test\n"})
        client.download_pack.return_value = zip_data

        syncer.sync()
        client.download_pack.reset_mock()

        # Second sync — should skip
        syncer.sync()
        client.download_pack.assert_not_called()

    def test_updates_when_version_changes(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        # First version
        client.get_available_packs.return_value = [
            {"enabled_id": 1, "pack_name": "pack1", "version": "1.0.0", "pack_version_id": 10, "autoupdate": True}
        ]
        client.download_pack.return_value = make_zip({"sigma/old.yml": "old"})
        syncer.sync()

        # New version (different pack_version_id)
        client.get_available_packs.return_value = [
            {"enabled_id": 1, "pack_name": "pack1", "version": "2.0.0", "pack_version_id": 11, "autoupdate": True}
        ]
        client.download_pack.return_value = make_zip({"sigma/new.yml": "new"})
        updated = syncer.sync()
        assert updated == 1
        assert (rules_dir / "sigma" / "pack1" / "new.yml").exists()


class TestExtraction:
    def test_infers_type_from_extension(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {"enabled_id": 1, "pack_name": "mixed", "version": "1.0.0", "pack_version_id": 20, "autoupdate": True}
        ]

        # Files at root level without subdirectories
        zip_data = make_zip({
            "detect_powershell.yaml": "title: PowerShell\n",
            "ransomware.yara": "rule ransom { condition: true }",
            "domains.txt": "evil.com;C2\n",
        })
        client.download_pack.return_value = zip_data

        syncer.sync()
        assert (rules_dir / "sigma" / "mixed" / "detect_powershell.yaml").exists()
        assert (rules_dir / "yara" / "mixed" / "ransomware.yara").exists()
        assert (rules_dir / "ioc" / "domains.txt").exists()

    def test_nested_directories_preserved(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {"enabled_id": 1, "pack_name": "deep", "version": "1.0.0", "pack_version_id": 30, "autoupdate": True}
        ]

        zip_data = make_zip({
            "sigma/windows/process_creation/mimikatz.yml": "title: Mimikatz\n",
            "yara/malware/trojan/agent.yar": "rule agent {}",
        })
        client.download_pack.return_value = zip_data

        syncer.sync()
        assert (rules_dir / "sigma" / "deep" / "windows" / "process_creation" / "mimikatz.yml").exists()
        assert (rules_dir / "yara" / "deep" / "malware" / "trojan" / "agent.yar").exists()


class TestManifestPersistence:
    def test_manifest_saved_and_loaded(self, setup_syncer):
        syncer, client, rules_dir, state_dir = setup_syncer

        client.get_available_packs.return_value = [
            {"enabled_id": 1, "pack_name": "pack1", "version": "1.0.0", "pack_version_id": 10, "autoupdate": True}
        ]
        client.download_pack.return_value = make_zip({"sigma/r.yml": "x"})
        syncer.sync()

        # Create a new syncer — should load manifest from disk
        syncer2 = PackSyncer(client, rules_dir, state_dir)
        client.download_pack.reset_mock()
        syncer2.sync()
        client.download_pack.assert_not_called()
