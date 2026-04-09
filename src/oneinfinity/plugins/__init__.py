"""
One&Infinity Plugin Package.

Plugins are auto-discovered by core.plugin_registry.PluginRegistry.discover().

Each plugin module must expose:
  PLUGIN_META = { "name", "type", "version", "description", "author", "tags" }
  class Plugin:
      def run(self, target: str, context: dict) -> dict: ...
"""
