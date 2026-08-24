// Entry point for the Mattermost Dex SSO webapp plugin.
// This file is bundled by webpack as a classic script and loaded into the
// Mattermost frontend. The host registers the plugin via
// `window.registerPlugin`, then calls `initialize(registry, store)` on the
// registered instance.
//
// The Mattermost plugin API has no login-page hook (plugin webapps do not
// load for anonymous users), so the Dex sign-in entry point is registered
// on the user menu ("main menu") instead. Clicking the item — or the button
// it renders — performs a full-page navigation to the plugin's /login route,
// which generates the OAuth state, sets the state cookie, and redirects the
// browser to the IdP. It also lets logged-in users switch Dex accounts.

import manifest from './manifest';
import type {ElementType, ReactNode} from 'react';

import DexLoginButton from './components/DexLoginButton';

// Same shape as the host's ReactResolvable: a React node or a component type
// the host will instantiate with React.createElement.
type ReactResolvable = ReactNode | ElementType;

// Minimal structural type for the host's PluginRegistry — only the
// registration API this plugin uses.
interface PluginRegistry {
    registerMainMenuAction(
        text: ReactResolvable,
        action: () => void,
        mobileIcon?: ReactResolvable
    ): string;
}

export default class Plugin {
    // Called by the Mattermost host after the bundle has been loaded.
    public initialize(registry: PluginRegistry, _store: unknown): void {
        // Register a user-menu entry for Dex sign-in. DexLoginButton fetches
        // the configured label/color from the plugin's public-config
        // endpoint; both the menu action and the button navigate to /login.
        registry.registerMainMenuAction(
            DexLoginButton,
            () => {
                window.location.href = '/plugins/com.mattermost.dex/login';
            },
            null
        );
    }
}

declare global {
    interface Window {
        registerPlugin(pluginId: string, plugin: Plugin): void;
    }
}

window.registerPlugin(manifest.id, new Plugin());
