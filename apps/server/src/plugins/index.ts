/**
 * Plugin manifest system: every capability = one folder + openmuse.plugin.json.
 * See docs/plugin-manifest.md for the convention.
 */
export { validateManifest, validatePluginConfig, applyConfigDefaults } from "./config-schema.ts";
export { discoverPlugins, defaultPluginRoots, MANIFEST_FILENAME } from "./discovery.ts";
export { loadPlugins, loadPluginSystem } from "./loader.ts";
export { PluginRegistry, resolvePluginConfig } from "./registry.ts";
export { pluginSystemRoutes } from "./routes.ts";
export type {
  DataBindingHandler,
  PluginActivation,
  PluginBindings,
  PluginContext,
  PluginModule,
  ToolRegistration,
  WorkerToolHost,
} from "./plugin-api.ts";
export type {
  DiscoveredPlugin,
  PluginManifest,
  PluginProblem,
  PluginStatus,
  PluginSummary,
  ToolKind,
  ToolMetadataEntry,
  ToolProvider,
} from "./types.ts";
