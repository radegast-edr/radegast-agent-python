"""Detection pack synchronization — downloads and extracts packs from the backend."""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any

from radegast_edr_agent.client import BackendClient

logger = logging.getLogger(__name__)

# Directories within a pack zip that map to radegast's rules structure
RULE_DIRS = {"sigma", "yara", "ioc"}
STANDARD_IOC_FILES = {"hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"}


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
        ensure_placeholders_and_ioc(self._rules_dir)

    def _load_manifest(self) -> dict[str, Any]:
        """Load the local manifest of installed pack versions."""
        if self._manifest_path.exists():
            data = json.loads(self._manifest_path.read_text())
            normalized: dict[str, Any] = {}
            for version_id, info in data.items():
                if isinstance(info, str):
                    normalized[version_id] = {"pack_id": None, "pack_name": None, "version": info}
                elif isinstance(info, dict):
                    normalized[version_id] = {
                        "pack_id": info.get("pack_id") or info.get("pack_name"),
                        "pack_name": info.get("pack_name"),
                        "version": info.get("version"),
                    }
                else:
                    normalized[version_id] = {"pack_id": None, "pack_name": None, "version": str(info)}
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
        self._manifest = self._load_manifest()
        self._ioc_registry = self._load_ioc_registry()
        available = self._client.get_available_packs()
        updated = 0

        enabled_ids = set()
        active_pack_ids = set()

        for pack_info in available:
            version_id = str(pack_info["pack_version_id"])
            pack_id = str(pack_info["pack_id"])
            pack_name = pack_info.get("pack_name")
            version = str(pack_info["version"])
            enabled_ids.add(version_id)
            active_pack_ids.add(pack_id)
            if pack_name:
                active_pack_ids.add(str(pack_name))

            existing = self._manifest.get(version_id)
            if existing and existing.get("pack_id") == pack_id and existing.get("version") == version:
                continue

            logger.info("Downloading pack '%s' version %s", pack_id, version)
            zip_data = self._client.download_pack(pack_info["pack_version_id"])
            new_ioc_files = self._extract_pack(zip_data, pack_id)
            self._manifest[version_id] = {
                "pack_id": pack_id,
                "pack_name": pack_name,
                "version": version,
            }
            self._update_ioc_registry_for_pack(pack_id, new_ioc_files)
            updated += 1

        removed_ids = set(self._manifest.keys()) - enabled_ids
        for vid in removed_ids:
            info = self._manifest[vid]
            pack_id = info.get("pack_id")
            pack_name = info.get("pack_name")
            if pack_id and pack_id not in active_pack_ids:
                self._remove_pack_ioc_references(pack_id)
                self._remove_pack_directories(pack_id, pack_name)
            del self._manifest[vid]

        # Clean up any stale packs remaining in IoC registry that are no longer active
        stale_ioc_packs = set()
        for filename, packs in list(self._ioc_registry.items()):
            for p in packs:
                if p not in active_pack_ids:
                    stale_ioc_packs.add(p)
        for p in stale_ioc_packs:
            self._remove_pack_ioc_references(p)
            self._remove_pack_directories(p)

        if updated or removed_ids or stale_ioc_packs:
            self._save_manifest()

        ensure_placeholders_and_ioc(self._rules_dir)

        if updated:
            logger.info("Pack sync complete: %d pack(s) updated", updated)
        else:
            logger.debug("Pack sync complete: no changes")

        return updated

    def _extract_pack(self, zip_data: bytes, pack_id: str) -> set[str]:
        """Extract a pack zip into the rules directory.

        Pack zips are expected to contain rule files organized in subdirectories:
        - sigma/  → extracted to rules/sigma/<pack_id>/
        - yara/   → extracted to rules/yara/<pack_id>/
        - ioc/    → extracted to state_dir/packs/<pack_id>/ioc/ and merged into rules/ioc/

        Files at the root or in unrecognized directories are placed under
        rules/sigma/<pack_id>/ if they have .yml/.yaml extension (excluding pack.yml),
        rules/yara/<pack_id>/ if .yar/.yara, or rules/ioc/ if .txt.
        """
        pack_ioc_dir = self._state_dir / "packs" / pack_id / "ioc"
        pack_ioc_dir.mkdir(parents=True, exist_ok=True)

        new_ioc_files: set[str] = set()
        written_rule_files: dict[str, set[Path]] = {"sigma": set(), "yara": set()}

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for member in zf.namelist():
                # Normalize path and skip directories
                normalized_member = member.replace("\\", "/")
                if normalized_member.endswith("/"):
                    continue

                parts = Path(normalized_member).parts
                filename = Path(normalized_member).name

                # Ignore pack metadata at root
                if len(parts) == 1 and filename.lower() in ("pack.yml", "pack.yaml"):
                    continue

                content = zf.read(member)

                if len(parts) > 1 and parts[0].lower() in RULE_DIRS:
                    rule_type = parts[0].lower()
                    if rule_type == "ioc":
                        ioc_target = pack_ioc_dir / filename
                        ioc_target.parent.mkdir(parents=True, exist_ok=True)
                        ioc_target.write_bytes(content)
                        new_ioc_files.add(filename)
                        continue
                    else:
                        target = self._rules_dir / rule_type / pack_id / Path(*parts[1:])
                        written_rule_files[rule_type].add(target.resolve())
                else:
                    ext = Path(filename).suffix.lower()
                    if ext in (".yml", ".yaml"):
                        target = self._rules_dir / "sigma" / pack_id / filename
                        written_rule_files["sigma"].add(target.resolve())
                    elif ext in (".yar", ".yara"):
                        target = self._rules_dir / "yara" / pack_id / filename
                        written_rule_files["yara"].add(target.resolve())
                    elif ext == ".txt":
                        ioc_target = pack_ioc_dir / filename
                        ioc_target.parent.mkdir(parents=True, exist_ok=True)
                        ioc_target.write_bytes(content)
                        new_ioc_files.add(filename)
                        continue
                    else:
                        target = self._rules_dir / "sigma" / pack_id / filename
                        written_rule_files["sigma"].add(target.resolve())

                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                logger.debug("Extracted: %s → %s", member, target)

        # Remove any old rule files in sigma/yara that were not in the new pack zip
        for rule_type, written_paths in written_rule_files.items():
            pack_dir = self._rules_dir / rule_type / pack_id
            if pack_dir.exists():
                for file_path in list(pack_dir.rglob("*")):
                    if file_path.is_file() and file_path.resolve() not in written_paths:
                        file_path.unlink()
                # Clean up any empty subdirectories
                for dir_path in sorted(pack_dir.rglob("*"), reverse=True):
                    if dir_path.is_dir() and not any(dir_path.iterdir()):
                        dir_path.rmdir()

        # Clean up any cached IoC files for this pack that were not in the new pack zip
        if pack_ioc_dir.exists():
            for ioc_file in list(pack_ioc_dir.glob("*")):
                if ioc_file.is_file() and ioc_file.name not in new_ioc_files:
                    ioc_file.unlink()

        return new_ioc_files

    def _update_ioc_registry_for_pack(self, pack_id: str, new_files: set[str]) -> None:
        current_files = {name for name, packs in self._ioc_registry.items() if pack_id in packs}
        affected_files = current_files | new_files

        for filename in new_files:
            packs = self._ioc_registry.setdefault(filename, [])
            if pack_id not in packs:
                packs.append(pack_id)

        for filename in current_files - new_files:
            packs = self._ioc_registry[filename]
            if pack_id in packs:
                packs.remove(pack_id)
            if not packs:
                del self._ioc_registry[filename]

        self._save_ioc_registry()

        for filename in affected_files:
            self._remerge_ioc_file(filename)

    def _remove_pack_ioc_references(self, pack_id: str) -> None:
        pack_ioc_dir = self._state_dir / "packs" / pack_id / "ioc"
        if pack_ioc_dir.exists():
            shutil.rmtree(pack_ioc_dir, ignore_errors=True)

        affected_files = set()
        for filename in list(self._ioc_registry.keys()):
            packs = self._ioc_registry[filename]
            if pack_id in packs:
                packs.remove(pack_id)
                affected_files.add(filename)
                if not packs:
                    del self._ioc_registry[filename]

        self._save_ioc_registry()

        for filename in affected_files:
            self._remerge_ioc_file(filename)

    def _remerge_ioc_file(self, filename: str) -> None:
        """Regenerate merged IoC file in rules/ioc/ from all active packs owning it."""
        target = self._rules_dir / "ioc" / filename
        target.parent.mkdir(parents=True, exist_ok=True)

        packs = self._ioc_registry.get(filename, [])
        if not packs:
            temp_file = target.with_name(f".{filename}.tmp")
            temp_file.write_text("", encoding="utf-8")
            os.replace(temp_file, target)
            return

        merged_lines: list[str] = []
        seen: set[str] = set()

        for p in packs:
            pack_file = self._state_dir / "packs" / p / "ioc" / filename
            if not pack_file.exists():
                continue
            text = pack_file.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped not in seen:
                    seen.add(stripped)
                    merged_lines.append(stripped)

        content = ("\n".join(merged_lines) + "\n") if merged_lines else ""
        temp_file = target.with_name(f".{filename}.tmp")
        temp_file.write_text(content, encoding="utf-8")
        os.replace(temp_file, target)

    def _ensure_empty_ioc_file(self, filename: str) -> None:
        target = self._rules_dir / "ioc" / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("")

    def _remove_pack_directories(self, pack_id: str, pack_name: str | None = None) -> None:
        pack_identifiers = {str(pack_id)}
        if pack_name:
            pack_identifiers.add(str(pack_name))

        for identifier in pack_identifiers:
            for rule_type in ("sigma", "yara"):
                target = self._rules_dir / rule_type / identifier
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
            pack_state = self._state_dir / "packs" / identifier
            if pack_state.exists():
                shutil.rmtree(pack_state, ignore_errors=True)


def ensure_placeholders_and_ioc(rules_dir: Path) -> None:
    """Ensure rule directories and required IoC files exist in the rules directory."""
    sigma_dir = rules_dir / "sigma"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    sigma_placeholder = sigma_dir / "placeholder.yml"
    if sigma_placeholder.exists():
        try:
            sigma_placeholder.unlink()
        except OSError:
            pass

    yara_dir = rules_dir / "yara"
    yara_dir.mkdir(parents=True, exist_ok=True)
    yara_placeholder = yara_dir / "placeholder.yar"
    if yara_placeholder.exists():
        try:
            yara_placeholder.unlink()
        except OSError:
            pass

    ioc_dir = rules_dir / "ioc"
    ioc_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"):
        ioc_file = ioc_dir / filename
        if not ioc_file.exists():
            ioc_file.write_text("")
