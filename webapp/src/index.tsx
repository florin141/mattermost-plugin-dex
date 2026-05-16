// Entry point for the Mattermost Dex SSO webapp plugin.
// This file is bundled by webpack and loaded into the Mattermost frontend.
// The DexLoginButton component is imported to register the login button.
import './components/DexLoginButton';

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface PluginRegistry {}

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export default class Plugin {
    public async executePlugin(_registry: PluginRegistry): Promise<void> {}
}
