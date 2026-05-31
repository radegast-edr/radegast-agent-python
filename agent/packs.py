"""Detection pack synchronization — downloads and extracts packs from the backend."""

from __future__ import annotations

import io
import json
import logging
import shutil
import zipfile
from pathlib import Path
from typing import Any

from agent.client import BackendClient

logger = logging.getLogger(__name__)

# Directories within a pack zip that map to radegast's rules structure
RULE_DIRS = {"sigma", "yara", "ioc"}


class PackSyncer:
    """Manages downloading and extracting detection packs into radegast's rules directory."""

    def __init__(self, client: BackendClient, rules_dir: Path, state_dir: Path):
        self._client = client
        self._rules_dir = rules_dir
        self._state_dir = state_dir
        self._manifest_path = state_dir / "packs.json"
        self._ioc_registry_path = self._rules_dir / "ioc" / "ioc_packs.json"
        self._manifest = self._load_manifest()
        self._ioc_registry = self._load_ioc_registry()

    def _load_manifest(self) -> dict[str, Any]:
        """Load the local manifest of installed pack versions."""
        if self._manifest_path.exists():
            data = json.loads(self._manifest_path.read_text())
            normalized: dict[str, Any] = {}
            for version_id, info in data.items():
                if isinstance(info, str):
                    normalized[version_id] = {"pack_name": None, "version": info}
                elif isinstance(info, dict):
                    normalized[version_id] = {
                        "pack_name": info.get("pack_name"),
                        "version": info.get("version"),
                    }
                else:
                    normalized[version_id] = {"pack_name": None, "version": str(info)}
            return normalized
        return {}

    def _save_manifest(self) -> None:
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._manifest_path.write_text(json.dumps(self._manifest, indent=2))

    def _load_ioc_registry(self) -> dict[str, list[str]]:
        if self._ioc_registry_path.exists():
            return json.loads(self._ioc_registry_path.read_text())
        return {}

    def _save_ioc_registry(self) -> None:
        self._ioc_registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._ioc_registry_path.write_text(json.dumps(self._ioc_registry, indent=2))

    def sync(self) -> int:
        """Sync packs from the backend. Returns number of packs updated."""
        available = self._client.get_available_packs()
        updated = 0

        enabled_ids = set()
        active_pack_names = set()

        for pack_info in available:
            version_id = str(pack_info["pack_version_id"])
            pack_name = pack_info["pack_name"]
            version = pack_info["version"]
            enabled_ids.add(version_id)
            active_pack_names.add(pack_name)

            existing = self._manifest.get(version_id)
            if existing and existing.get("pack_name") == pack_name and existing.get("version") == version:
                continue

            logger.info("Downloading pack '%s' version %s", pack_name, version)
            zip_data = self._client.download_pack(pack_info["pack_version_id"])
            new_ioc_files = self._extract_pack(zip_data, pack_name)
            self._manifest[version_id] = {"pack_name": pack_name, "version": version}
            self._update_ioc_registry_for_pack(pack_name, new_ioc_files)
            updated += 1

        removed_ids = set(self._manifest.keys()) - enabled_ids
        for vid in removed_ids:
            pack_name = self._manifest[vid].get("pack_name")
            if pack_name and pack_name not in active_pack_names:
                self._remove_pack_ioc_references(pack_name)
                self._remove_pack_directories(pack_name)
            del self._manifest[vid]

        if updated or removed_ids:
            self._save_manifest()

        if updated:
            logger.info("Pack sync complete: %d pack(s) updated", updated)
        else:
            logger.debug("Pack sync complete: no changes")

        return updated

    def _extract_pack(self, zip_data: bytes, pack_name: str) -> set[str]:
        """Extract a pack zip into the rules directory.

        Pack zips are expected to contain rule files organized in subdirectories:
        - sigma/  → extracted to rules/sigma/<pack_name>/
        - yara/   → extracted to rules/yara/<pack_name>/
        - ioc/    → extracted to rules/ioc/ (merged, not namespaced)

        Files at the root or in unrecognized directories are placed under
        rules/sigma/<pack_name>/ if they have .yml/.yaml extension,
        rules/yara/<pack_name>/ if .yar/.yara, or rules/ioc/ if .txt.
        """
        new_ioc_files: set[str] = set()

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for member in zf.namelist():
                # Skip directories themselves
                if member.endswith("/"):
                    continue

                parts = Path(member).parts
                content = zf.read(member)
                filename = Path(member).name

                if len(parts) > 1 and parts[0].lower() in RULE_DIRS:
                    rule_type = parts[0].lower()
                    if rule_type == "ioc":
                        target = self._rules_dir / "ioc" / filename
                        new_ioc_files.add(filename)
                    else:
                        target = self._rules_dir / rule_type / pack_name / Path(*parts[1:])
                else:
                    ext = Path(filename).suffix.lower()
                    if ext in (".yml", ".yaml"):
                        target = self._rules_dir / "sigma" / pack_name / filename
                    elif ext in (".yar", ".yara"):
                        target = self._rules_dir / "yara" / pack_name / filename
                    elif ext == ".txt":
                        target = self._rules_dir / "ioc" / filename
                        new_ioc_files.add(filename)
                    else:
                        target = self._rules_dir / "sigma" / pack_name / filename

                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                logger.debug("Extracted: %s → %s", member, target)

        return new_ioc_files

    def _update_ioc_registry_for_pack(self, pack_name: str, new_files: set[str]) -> None:
        current_files = {name for name, packs in self._ioc_registry.items() if pack_name in packs}

        for filename in new_files:
            packs = self._ioc_registry.setdefault(filename, [])
            if pack_name not in packs:
                packs.append(pack_name)

        for filename in current_files - new_files:
            packs = self._ioc_registry[filename]
            packs.remove(pack_name)
            if not packs:
                del self._ioc_registry[filename]
                self._ensure_empty_ioc_file(filename)

        self._save_ioc_registry()

    def _remove_pack_ioc_references(self, pack_name: str) -> None:
        for filename in list(self._ioc_registry.keys()):
            packs = self._ioc_registry[filename]
            if pack_name not in packs:
                continue
            packs.remove(pack_name)
            if not packs:
                del self._ioc_registry[filename]
                self._ensure_empty_ioc_file(filename)

        self._save_ioc_registry()

    def _ensure_empty_ioc_file(self, filename: str) -> None:
        target = self._rules_dir / "ioc" / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("")

    def _remove_pack_directories(self, pack_name: str) -> None:
        for rule_type in ("sigma", "yara"):
            target = self._rules_dir / rule_type / pack_name
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
