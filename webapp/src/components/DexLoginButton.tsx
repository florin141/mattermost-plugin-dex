import React, {useEffect, useState} from 'react';

interface PublicConfig {
    issuerUrl: string;
    clientId: string;
    buttonLabel: string;
    buttonColor: string;
    redirectUrl: string;
}

const defaultStyles: Record<string, React.CSSProperties> = {
    button: {
        width: '100%',
        padding: '10px 12px',
        border: 'none',
        borderRadius: '4px',
        fontSize: '14px',
        fontWeight: '500',
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        color: '#ffffff',
        backgroundColor: '#009EDB',
        marginBottom: '8px',
    },
    errorBanner: {
        marginBottom: '8px',
        padding: '8px 12px',
        borderRadius: '4px',
        backgroundColor: '#fdecea',
        color: '#c0392b',
        fontSize: '13px',
    },
    container: {
        width: '100%',
    },
};

const DexLoginButton: React.FC = () => {
    const [config, setConfig] = useState<PublicConfig | null>(null);
    const [loading, setLoading] = useState(true);
    const [oauthError, setOauthError] = useState<string | null>(null);
    const [buttonColor, setButtonColor] = useState('#009EDB');

    useEffect(() => {
        // Check for OAuth error from Dex redirect
        const params = new URLSearchParams(window.location.search);
        const err = params.get('error');
        const desc = params.get('error_description');
        if (err) {
            setOauthError(desc ?? err);
            // Clear the error params after showing the banner
            const newParams = new URLSearchParams();
            for (const [key, value] of params.entries()) {
                if (key !== 'error' && key !== 'error_description') {
                    newParams.set(key, value);
                }
            }
            const queryString = newParams.toString();
            const newUrl = queryString
                ? `${window.location.pathname}?${queryString}`
                : window.location.pathname;
            window.history.replaceState({}, '', newUrl);
            return;
        }
    }, []);

    useEffect(() => {
        const fetchConfig = async () => {
            try {
                // Fetch public config from the plugin's server endpoint
                const response = await fetch('/plugins/com.example.dex-sso/api/public-config');
                if (!response.ok) {
                    // Fall back to defaults silently
                    setButtonColor('#009EDB');
                    setLoading(false);
                    return;
                }
                const data: PublicConfig = await response.json();
                setConfig(data);
                if (data.buttonColor) {
                    setButtonColor(data.buttonColor);
                }
            } catch (err) {
                // Fetch failed — fall back to defaults silently
                setButtonColor('#009EDB');
            } finally {
                setLoading(false);
            }
        };
        fetchConfig();
    }, []);

    const handleLogin = () => {
        if (!config?.issuerUrl || !config?.clientId) {
            return;
        }

        // Build the Dex authorization URL
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUrl || window.location.origin + '/plugins/com.example.dex-sso/callback',
            scope: 'openid profile email',
            state: generateState(),
            audience: config.issuerUrl,
        });

        const authUrl = `${config.issuerUrl}/auth?${params.toString()}`;
        window.location.href = authUrl;
    };

    const generateState = (): string => {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
    };

    if (loading || !config) {
        return null;
    }

    return (
        <div style={defaultStyles.container}>
            {oauthError && (
                <div style={defaultStyles.errorBanner} role="alert">
                    Sign-in failed: {oauthError}
                </div>
            )}
            <button
                style={{...defaultStyles.button, backgroundColor: buttonColor}}
                onClick={handleLogin}
                type="button"
            >
                {config.buttonLabel || 'Sign in with Dex'}
            </button>
        </div>
    );
};

export default DexLoginButton;
