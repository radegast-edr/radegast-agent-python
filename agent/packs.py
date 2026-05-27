"""Detection pack synchronization — downloads and extracts packs from the backend."""

from __future__ import annotations

import io
import json
import logging
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
        self._manifest = self._load_manifest()

    def _load_manifest(self) -> dict[str, Any]:
        """Load the local manifest of installed pack versions."""
        if self._manifest_path.exists():
            return json.loads(self._manifest_path.read_text())
        return {}

    def _save_manifest(self) -> None:
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._manifest_path.write_text(json.dumps(self._manifest, indent=2))

    def sync(self) -> int:
        """Sync packs from the backend. Returns number of packs updated."""
        available = self._client.get_available_packs()
        updated = 0

        # Build set of currently-enabled version IDs
        enabled_ids = set()

        for pack_info in available:
            version_id = str(pack_info["pack_version_id"])
            pack_name = pack_info["pack_name"]
            version = pack_info["version"]
            enabled_ids.add(version_id)

            # Skip if already installed at this version
            if self._manifest.get(version_id) == version:
                continue

            logger.info("Downloading pack '%s' version %s", pack_name, version)
            zip_data = self._client.download_pack(pack_info["pack_version_id"])
            self._extract_pack(zip_data, pack_name)
            self._manifest[version_id] = version
            updated += 1

        # Remove packs that are no longer enabled
        removed_ids = set(self._manifest.keys()) - enabled_ids
        for vid in removed_ids:
            del self._manifest[vid]

        if updated or removed_ids:
            self._save_manifest()

        if updated:
            logger.info("Pack sync complete: %d pack(s) updated", updated)
        else:
            logger.debug("Pack sync complete: no changes")

        return updated

    def _extract_pack(self, zip_data: bytes, pack_name: str) -> None:
        """Extract a pack zip into the rules directory.

        Pack zips are expected to contain rule files organized in subdirectories:
        - sigma/  → extracted to rules/sigma/<pack_name>/
        - yara/   → extracted to rules/yara/<pack_name>/
        - ioc/    → extracted to rules/ioc/ (merged, not namespaced)

        Files at the root or in unrecognized directories are placed under
        rules/sigma/<pack_name>/ if they have .yml/.yaml extension,
        rules/yara/<pack_name>/ if .yar/.yara, or rules/ioc/ if .txt.
        """
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for member in zf.namelist():
                # Skip directories themselves
                if member.endswith("/"):
                    continue

                # Determine target location
                parts = Path(member).parts
                content = zf.read(member)
                filename = Path(member).name

                if len(parts) > 1 and parts[0].lower() in RULE_DIRS:
                    rule_type = parts[0].lower()
                    if rule_type == "ioc":
                        target = self._rules_dir / "ioc" / filename
                    else:
                        target = self._rules_dir / rule_type / pack_name / Path(*parts[1:])
                else:
                    # Infer from extension
                    ext = Path(filename).suffix.lower()
                    if ext in (".yml", ".yaml"):
                        target = self._rules_dir / "sigma" / pack_name / filename
                    elif ext in (".yar", ".yara"):
                        target = self._rules_dir / "yara" / pack_name / filename
                    elif ext == ".txt":
                        target = self._rules_dir / "ioc" / filename
                    else:
                        target = self._rules_dir / "sigma" / pack_name / filename

                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                logger.debug("Extracted: %s → %s", member, target)
