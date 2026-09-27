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
        assert (rules_dir / "ioc" / "hashes.txt").read_text() == "abc123;test hash\ndef456;other hash\n"

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
        assert (rules_dir / "ioc" / "hashes.txt").read_text() == "def456;other hash\n"

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
        assert (rules_dir / "ioc" / "hashes.txt").read_text() == "abc123;hash1\ndef456;hash2\n"

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
        assert (rules_dir / "ioc" / "hashes.txt").read_text() == "abc123;hash1\n"
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


class TestPackUpdatesAndIoCMerging:
    def test_merged_ioc_content_across_multiple_packs(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack-a",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            },
            {
                "enabled_id": 2,
                "pack_id": "pack-b",
                "version": "1.0.0",
                "pack_version_id": 20,
                "autoupdate": True,
            },
        ]

        client.download_pack.side_effect = [
            make_zip({"ioc/ips.txt": "1.1.1.1\n1.1.1.2\n"}),
            make_zip({"ioc/ips.txt": "1.1.1.2\n2.2.2.2\n"}),
        ]

        syncer.sync()

        # Both packs should be in registry and merged deduplicated in rules/ioc/ips.txt
        registry = json.loads((rules_dir / "ioc" / "ioc_packs.json").read_text())
        assert registry == {"ips.txt": ["pack-a", "pack-b"]}
        ips_content = (rules_dir / "ioc" / "ips.txt").read_text()
        assert ips_content == "1.1.1.1\n1.1.1.2\n2.2.2.2\n"

        # Remove pack-b
        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "pack-a",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]
        syncer.sync()

        # Only pack-a should remain in registry and only its IoCs in rules/ioc/ips.txt
        registry = json.loads((rules_dir / "ioc" / "ioc_packs.json").read_text())
        assert registry == {"ips.txt": ["pack-a"]}
        ips_content = (rules_dir / "ioc" / "ips.txt").read_text()
        assert ips_content == "1.1.1.1\n1.1.1.2\n"

        # Remove pack-a as well
        client.get_available_packs.return_value = []
        syncer.sync()

        registry = json.loads((rules_dir / "ioc" / "ioc_packs.json").read_text())
        assert registry == {}
        assert (rules_dir / "ioc" / "ips.txt").read_text() == ""

    def test_update_pack_removes_old_sigma_and_yara_rules(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        # Version 1.0.0
        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "threat-pack",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip(
            {
                "sigma/rule_old.yml": "title: Old Rule\n",
                "sigma/rule_kept.yml": "title: Kept Rule\n",
                "yara/malware_old.yar": "rule OldMalware { condition: true }",
            }
        )
        syncer.sync()

        assert (rules_dir / "sigma" / "threat-pack" / "rule_old.yml").exists()
        assert (rules_dir / "sigma" / "threat-pack" / "rule_kept.yml").exists()
        assert (rules_dir / "yara" / "threat-pack" / "malware_old.yar").exists()

        # Version 2.0.0 removes rule_old.yml and malware_old.yar, adds rule_new.yml and malware_new.yar
        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "threat-pack",
                "version": "2.0.0",
                "pack_version_id": 11,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip(
            {
                "sigma/rule_kept.yml": "title: Kept Rule Updated\n",
                "sigma/rule_new.yml": "title: New Rule\n",
                "yara/malware_new.yar": "rule NewMalware { condition: true }",
            }
        )
        syncer.sync()

        # Verify old rules are deleted and only new/kept rules exist
        assert not (rules_dir / "sigma" / "threat-pack" / "rule_old.yml").exists()
        assert not (rules_dir / "yara" / "threat-pack" / "malware_old.yar").exists()
        assert (rules_dir / "sigma" / "threat-pack" / "rule_kept.yml").exists()
        assert (rules_dir / "sigma" / "threat-pack" / "rule_new.yml").exists()
        assert (rules_dir / "yara" / "threat-pack" / "malware_new.yar").exists()

    def test_modify_pack_content_removes_deleted_iocs(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        # Version 1.0.0 has two hashes
        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "ioc-pack",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip(
            {
                "ioc/hashes.txt": "hash1;first\nhash2;second\n",
            }
        )
        syncer.sync()

        assert (rules_dir / "ioc" / "hashes.txt").read_text() == "hash1;first\nhash2;second\n"

        # Version 2.0.0 removes hash2 and adds hash3
        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "ioc-pack",
                "version": "2.0.0",
                "pack_version_id": 11,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip(
            {
                "ioc/hashes.txt": "hash1;first\nhash3;third\n",
            }
        )
        syncer.sync()

        # hash2 should no longer be present
        assert (rules_dir / "ioc" / "hashes.txt").read_text() == "hash1;first\nhash3;third\n"

    def test_pack_yml_not_extracted_as_sigma_rule(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        client.get_available_packs.return_value = [
            {
                "enabled_id": 1,
                "pack_id": "my-pack",
                "version": "1.0.0",
                "pack_version_id": 10,
                "autoupdate": True,
            }
        ]
        client.download_pack.return_value = make_zip(
            {
                "pack.yml": "name: My Pack\nversion: 1.0.0\n",
                "sigma/test.yml": "title: Test Rule\n",
            }
        )
        syncer.sync()

        # pack.yml must NOT be extracted into rules/sigma/my-pack/pack.yml
        assert not (rules_dir / "sigma" / "my-pack" / "pack.yml").exists()
        assert (rules_dir / "sigma" / "my-pack" / "test.yml").exists()

    def test_stale_ioc_registry_cleaned_on_sync(self, setup_syncer):
        syncer, client, rules_dir, _ = setup_syncer

        # Pre-seed stale registry entry and file
        (rules_dir / "ioc" / "ioc_packs.json").write_text(json.dumps({"ips.txt": ["stale-pack"]}))
        (rules_dir / "ioc" / "ips.txt").write_text("1.2.3.4\n")
        (rules_dir / "sigma" / "stale-pack").mkdir(parents=True, exist_ok=True)
        (rules_dir / "sigma" / "stale-pack" / "rule.yml").write_text("title: Stale\n")

        # Sync with no packs enabled
        client.get_available_packs.return_value = []
        syncer.sync()

        # Should self-heal: stale pack cleaned from registry, ioc file cleared, directories removed
        registry = json.loads((rules_dir / "ioc" / "ioc_packs.json").read_text())
        assert registry == {}
        assert (rules_dir / "ioc" / "ips.txt").read_text() == ""
        assert not (rules_dir / "sigma" / "stale-pack").exists()
