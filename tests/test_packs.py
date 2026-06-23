"""Tests for the pack syncer."""

import io
import json
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from radegast_edr_agent.packs import PackSyncer


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
                "pack_id": "threat-intel",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]

        zip_data = make_zip(
            {
                "sigma/detect_mimikatz.yml": "title: Mimikatz\n",
                "yara/malware.yar": "rule test { condition: true }",
                "ioc/hashes.txt": "abc123;test hash\n",
            }
        )
        client.download_pack.return_value = zip_data

        updated = syncer.sync()
        assert updated == 1

        # Verify extraction
        assert (rules_dir / "sigma" / "threat-intel" / "detect_mimikatz.yml").exists()
        assert (rules_dir / "yara" / "threat-intel" / "malware.yar").exists()
        assert (rules_dir / "ioc" / "hashes.txt").exists()

        registry_path = rules_dir / "ioc" / "ioc_packs.json"
        assert registry_path.exists()
        registry = json.loads(registry_path.read_text())
        assert registry == {"hashes.txt": ["threat-intel"]}

    def test_removes_ioc_file_when_pack_is_removed(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack1",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            },
            {
                "enabled_id": 2,
                "pack_id": "pack2",
                "version": "1.0.0",
                "pack_version_id": 20,
                "autoupdate": True,
            },
        ]

        client.download_pack.side_effect = [
            make_zip({"ioc/hashes.txt": "abc123;test hash\n"}),
            make_zip({"ioc/hashes.txt": "def456;other hash\n"}),
        ]

        syncer.sync()
        registry_path = rules_dir / "ioc" / "ioc_packs.json"
        assert registry_path.exists()
        registry = json.loads(registry_path.read_text())
        assert registry == {"hashes.txt": ["pack1", "pack2"]}
        assert (rules_dir / "ioc" / "hashes.txt").exists()

        client.get_available_packs.return_value = [
            {
                "enabled_id": 2,
                "pack_id": "pack2",
                "version": "1.0.0",
                "pack_version_id": 20,
                "autoupdate": True,
            }
        ]
        syncer.sync()

        registry = json.loads(registry_path.read_text())
        assert registry == {"hashes.txt": ["pack2"]}
        assert (rules_dir / "ioc" / "hashes.txt").exists()

        client.get_available_packs.return_value = []
        syncer.sync()

        assert (rules_dir / "ioc" / "hashes.txt").exists()
        assert (rules_dir / "ioc" / "hashes.txt").read_text() == ""
        assert json.loads(registry_path.read_text()) == {}

    def test_updates_pack_removes_old_ioc_files(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack1",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]

        client.download_pack.return_value = make_zip(
            {
                "ioc/old.txt": "oldhash\n",
                "ioc/common.txt": "commonhash\n",
            }
        )
        syncer.sync()

        assert (rules_dir / "ioc" / "old.txt").exists()
        assert (rules_dir / "ioc" / "common.txt").exists()

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack1",
                "version": "2.0.0",
                "pack_version_id": 11,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip({"ioc/common.txt": "newhash\n"})
        syncer.sync()

        assert (rules_dir / "ioc" / "old.txt").exists()
        assert (rules_dir / "ioc" / "old.txt").read_text() == ""
        assert (rules_dir / "ioc" / "common.txt").exists()
        registry_path = rules_dir / "ioc" / "ioc_packs.json"
        registry = json.loads(registry_path.read_text())
        assert registry == {"common.txt": ["pack1"]}

    def test_adds_and_removes_packs_with_yara_and_ioc(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "yara-one",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            },
            {
                "enabled_id": 2,
                "pack_id": "yara-two",
                "version": "1.0.0",
                "pack_version_id": 20,
                "autoupdate": True,
            },
            {
                "enabled_id": 3,
                "pack_id": "ioc-one",
                "version": "1.0.0",
                "pack_version_id": 30,
                "autoupdate": True,
            },
            {
                "enabled_id": 4,
                "pack_id": "ioc-two",
                "version": "1.0.0",
                "pack_version_id": 40,
                "autoupdate": True,
            },
        ]

        client.download_pack.side_effect = [
            make_zip({"yara/malware_one.yar": "rule malware_one { condition: true }"}),
            make_zip({"yara/malware_two.yar": "rule malware_two { condition: true }"}),
            make_zip({"ioc/hashes.txt": "abc123;hash1\n"}),
            make_zip({"ioc/hashes.txt": "def456;hash2\n"}),
        ]

        syncer.sync()

        assert (rules_dir / "yara" / "yara-one" / "malware_one.yar").exists()
        assert (rules_dir / "yara" / "yara-two" / "malware_two.yar").exists()
        assert (rules_dir / "ioc" / "hashes.txt").exists()

        registry_path = rules_dir / "ioc" / "ioc_packs.json"
        registry = json.loads(registry_path.read_text())
        assert registry == {"hashes.txt": ["ioc-one", "ioc-two"]}

        client.download_pack.reset_mock()

        client.get_available_packs.return_value = [
            {
                "enabled_id": 2,
                "pack_id": "yara-two",
                "version": "1.0.0",
                "pack_version_id": 20,
                "autoupdate": True,
            },
            {
                "enabled_id": 3,
                "pack_id": "ioc-one",
                "version": "1.0.0",
                "pack_version_id": 30,
                "autoupdate": True,
            },
        ]

        syncer.sync()

        assert not (rules_dir / "yara" / "yara-one").exists()
        assert (rules_dir / "yara" / "yara-two" / "malware_two.yar").exists()
        assert (rules_dir / "ioc" / "hashes.txt").exists()
        assert json.loads(registry_path.read_text()) == {"hashes.txt": ["ioc-one"]}
        client.download_pack.assert_not_called()

        client.get_available_packs.return_value = []
        syncer.sync()

        assert not (rules_dir / "yara" / "yara-two").exists()
        assert (rules_dir / "ioc" / "hashes.txt").exists()
        assert (rules_dir / "ioc" / "hashes.txt").read_text() == ""
        assert json.loads(registry_path.read_text()) == {}

    def test_skips_already_installed(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack1",
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
            {
                "enabled_id": 1,
                "pack_id": "pack1",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip({"sigma/old.yml": "old"})
        syncer.sync()

        # New version (different pack_version_id)
        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack1",
                "version": "2.0.0",
                "pack_version_id": 11,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip({"sigma/new.yml": "new"})
        updated = syncer.sync()
        assert updated == 1
        assert (rules_dir / "sigma" / "pack1" / "new.yml").exists()


class TestExtraction:
    def test_infers_type_from_extension(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "mixed",
                "version": "1.0.0",
                "pack_version_id": 20,
                "autoupdate": True,
            }
        ]

        # Files at root level without subdirectories
        zip_data = make_zip(
            {
                "detect_powershell.yaml": "title: PowerShell\n",
                "ransomware.yara": "rule ransom { condition: true }",
                "domains.txt": "evil.com;C2\n",
            }
        )
        client.download_pack.return_value = zip_data

        syncer.sync()
        assert (rules_dir / "sigma" / "mixed" / "detect_powershell.yaml").exists()
        assert (rules_dir / "yara" / "mixed" / "ransomware.yara").exists()
        assert (rules_dir / "ioc" / "domains.txt").exists()

    def test_nested_directories_preserved(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "deep",
                "version": "1.0.0",
                "pack_version_id": 30,
                "autoupdate": True,
            }
        ]

        zip_data = make_zip(
            {
                "sigma/windows/process_creation/mimikatz.yml": "title: Mimikatz\n",
                "yara/malware/trojan/radegast_edr_agent.yar": "rule agent {}",
            }
        )
        client.download_pack.return_value = zip_data

        syncer.sync()
        assert (rules_dir / "sigma" / "deep" / "windows" / "process_creation" / "mimikatz.yml").exists()
        assert (rules_dir / "yara" / "deep" / "malware" / "trojan" / "radegast_edr_agent.yar").exists()


class TestManifestPersistence:
    def test_manifest_saved_and_loaded(self, setup_syncer):
        syncer, client, rules_dir, state_dir = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack1",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip({"sigma/r.yml": "x"})
        syncer.sync()

        # Create a new syncer — should load manifest from disk
        syncer2 = PackSyncer(client, rules_dir, state_dir)
        client.download_pack.reset_mock()
        syncer2.sync()
        client.download_pack.assert_not_called()


class TestPlaceholdersAndIOC:
    def test_ensures_placeholders_on_init(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        # Placeholders should NOT exist
        assert not (rules_dir / "sigma" / "placeholder.yml").exists()
        assert not (rules_dir / "yara" / "placeholder.yar").exists()
        for filename in ("hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"):
            assert (rules_dir / "ioc" / filename).exists()

    def test_ensures_placeholders_on_sync(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        # Delete the IoC files
        (rules_dir / "ioc" / "hashes.txt").unlink()

        # Run sync
        client.get_available_packs.return_value = []
        syncer.sync()

        # Placeholders should still NOT exist, but IoC files should be recreated
        assert not (rules_dir / "sigma" / "placeholder.yml").exists()
        assert not (rules_dir / "yara" / "placeholder.yar").exists()
        assert (rules_dir / "ioc" / "hashes.txt").exists()
