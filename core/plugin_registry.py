"""
Plugin Registry — auto-discover and manage scanner plugins.

Plugin types:
  recon  — subdomain/URL/endpoint discovery
  vuln   — vulnerability testing
  report — output formatters

Each plugin must expose:
  PLUGIN_META = {
      "name": str,
      "type": "recon" | "vuln" | "report",
      "version": str,
      "description": str,
      "author": str,
      "tags": [str],
  }

  class Plugin:
      def run(self, target: str, context: dict) -> dict:
          ...
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import pkgutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

log = logging.getLogger(__name__)

PLUGIN_TYPES = {"recon", "vuln", "report"}


@dataclass
class PluginEntry:
    name: str
    plugin_type: str
    version: str
    description: str
    author: str
    tags: List[str]
    module_path: str
    plugin_class: Type
    enabled: bool = True


class PluginRegistry:
    """Central registry for all scanner plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, PluginEntry] = {}
        self._hooks: Dict[str, List[Callable]] = {}

    # ------------------------------------------------------------------ #
    #  Discovery
    # ------------------------------------------------------------------ #

    def discover(self, plugins_dir: Optional[Path] = None) -> int:
        """
        Auto-discover plugins from the plugins/ directory tree.
        Returns number of newly registered plugins.
        """
        if plugins_dir is None:
            plugins_dir = Path(__file__).parent.parent / "plugins"

        if not plugins_dir.exists():
            log.warning("plugins/ directory not found: %s", plugins_dir)
            return 0

        count = 0
        for finder, module_name, is_pkg in pkgutil.walk_packages(
            path=[str(plugins_dir)],
            prefix="plugins.",
            onerror=lambda name: log.error("Error walking %s", name),
        ):
            if is_pkg:
                continue
            try:
                mod = importlib.import_module(module_name)
                if self._register_module(mod, module_name):
                    count += 1
            except Exception as exc:
                log.error("Failed to load plugin %s: %s", module_name, exc)

        log.info("Discovered %d plugin(s) from %s", count, plugins_dir)
        return count

    def load_file(self, path: Path) -> bool:
        """Load a single plugin file by path."""
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            return False
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception as exc:
            log.error("Failed to load %s: %s", path, exc)
            return False
        sys.modules[path.stem] = mod
        return self._register_module(mod, str(path))

    def _register_module(self, mod: Any, module_path: str) -> bool:
        """Extract PLUGIN_META + Plugin class and register."""
        meta = getattr(mod, "PLUGIN_META", None)
        if meta is None:
            return False

        plugin_class = getattr(mod, "Plugin", None)
        if plugin_class is None or not inspect.isclass(plugin_class):
            log.warning("Plugin module %s missing 'Plugin' class", module_path)
            return False

        ptype = meta.get("type", "")
        if ptype not in PLUGIN_TYPES:
            log.warning("Unknown plugin type '%s' in %s", ptype, module_path)
            return False

        name = meta.get("name", module_path)
        entry = PluginEntry(
            name=name,
            plugin_type=ptype,
            version=meta.get("version", "0.0.1"),
            description=meta.get("description", ""),
            author=meta.get("author", "unknown"),
            tags=meta.get("tags", []),
            module_path=module_path,
            plugin_class=plugin_class,
        )
        self._plugins[name] = entry
        log.debug("Registered plugin: %s (%s)", name, ptype)
        return True

    # ------------------------------------------------------------------ #
    #  Query
    # ------------------------------------------------------------------ #

    def get(self, name: str) -> Optional[PluginEntry]:
        return self._plugins.get(name)

    def list_all(self) -> List[PluginEntry]:
        return list(self._plugins.values())

    def list_by_type(self, plugin_type: str) -> List[PluginEntry]:
        return [p for p in self._plugins.values() if p.plugin_type == plugin_type]

    def list_by_tag(self, tag: str) -> List[PluginEntry]:
        return [p for p in self._plugins.values() if tag in p.tags]

    def is_registered(self, name: str) -> bool:
        return name in self._plugins

    # ------------------------------------------------------------------ #
    #  Execution
    # ------------------------------------------------------------------ #

    def run_plugin(self, name: str, target: str, context: Optional[dict] = None) -> dict:
        """Instantiate and run a plugin by name."""
        entry = self._plugins.get(name)
        if entry is None:
            raise KeyError(f"Plugin '{name}' not found")
        if not entry.enabled:
            raise RuntimeError(f"Plugin '{name}' is disabled")
        ctx = context or {}
        instance = entry.plugin_class()
        self._fire("before_plugin_run", name=name, target=target, context=ctx)
        result = instance.run(target, ctx)
        self._fire("after_plugin_run", name=name, target=target, result=result)
        return result

    def run_all_by_type(
        self, plugin_type: str, target: str, context: Optional[dict] = None
    ) -> Dict[str, dict]:
        """Run all enabled plugins of a given type and return name→result map."""
        results: Dict[str, dict] = {}
        for entry in self.list_by_type(plugin_type):
            if not entry.enabled:
                continue
            try:
                results[entry.name] = self.run_plugin(entry.name, target, context)
            except Exception as exc:
                log.error("Plugin %s failed: %s", entry.name, exc)
                results[entry.name] = {"error": str(exc)}
        return results

    # ------------------------------------------------------------------ #
    #  Hooks
    # ------------------------------------------------------------------ #

    def on(self, event: str, callback: Callable) -> None:
        self._hooks.setdefault(event, []).append(callback)

    def _fire(self, event: str, **kwargs: Any) -> None:
        for cb in self._hooks.get(event, []):
            try:
                cb(**kwargs)
            except Exception as exc:
                log.error("Hook error [%s]: %s", event, exc)

    # ------------------------------------------------------------------ #
    #  Management
    # ------------------------------------------------------------------ #

    def enable(self, name: str) -> None:
        if name in self._plugins:
            self._plugins[name].enabled = True

    def disable(self, name: str) -> None:
        if name in self._plugins:
            self._plugins[name].enabled = False

    def unregister(self, name: str) -> None:
        self._plugins.pop(name, None)

    def summary(self) -> str:
        lines = [f"Plugin Registry — {len(self._plugins)} plugin(s)"]
        for ptype in PLUGIN_TYPES:
            subset = self.list_by_type(ptype)
            if subset:
                lines.append(f"  {ptype}: {', '.join(p.name for p in subset)}")
        return "\n".join(lines)


# Global singleton
plugin_registry = PluginRegistry()
