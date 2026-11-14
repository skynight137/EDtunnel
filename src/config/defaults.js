/**
 * Default configuration values
 */

/**
 * Default user ID (UUID format)
 * Generate UUID: [Windows] Press "Win + R", input cmd and run: Powershell -NoExit -Command "[guid]::NewGuid()"
 */
export const defaultUserID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

/**
 * Default Trojan password
 * If empty, uses the UUID as password
 */
export const defaultTrojanPassword = '';

/**
 * Array of proxy server addresses with ports
 * Format: ['hostname:port', 'hostname:port']
 */
export const proxyIPs = ['cdn.xn--b6gac.eu.org:443', 'cdn-all.xn--b6gac.eu.org:443'];

/**
 * Default SOCKS5 proxy configuration
 * Format: 'username:password@host:port' or 'host:port'
 */
export const defaultSocks5Address = '';

/**
 * Default SOCKS5 relay mode
 * When true: All traffic is proxied through SOCKS5
 * When false: Only Cloudflare IPs use SOCKS5
 */
export const defaultSocks5Relay = false;

/**
 * Default proxy connection timeout in milliseconds
 * Used when rotating through multiple proxy addresses
 */
export const defaultProxyTimeout = 1500;

/**
 * Default proxy fallback setting
 * When true: Falls back to direct connection if all proxies fail
 * When false: Fails immediately if all proxies fail
 */
export const defaultEnableProxyFallback = true;

/**
 * Default VLESS outbound configuration
 * Format: 'vless://uuid@host:port?type=ws&security=tls&path=/path'
 */
export const defaultVlessOutbound = '';

/**
 * Default bestIP endpoint base URL
 * The /bestip/{uuid} route fetches {BESTIP_URL}/auto?host=...&uuid=...&path=/
 * from this host. Override with the BESTIP_URL environment variable to point
 * at a self-hosted bestIP (a different Worker, a VPS, a repl) instead of the
 * public default.
 */
export const defaultBestipUrl = 'https://bestip.06151953.xyz';

/**
 * Creates a request configuration object with default values
 * @param {Object} env - Environment variables
 * @param {string} env.UUID - User ID for authentication
 * @param {string} env.SOCKS5 - SOCKS5 proxy configuration
 * @param {string} env.SOCKS5_RELAY - SOCKS5 relay mode flag
 * @param {string} env.TROJAN_PASSWORD - Trojan password (optional, uses UUID if not set)
 * @param {string} env.PROXY_TIMEOUT - Proxy connection timeout in ms
 * @param {string} env.PROXY_FALLBACK - Enable fallback to direct connection
 * @param {string} env.VLESS_OUTBOUND - VLESS outbound configuration URL
 * @param {string} env.BESTIP_URL - bestIP endpoint base URL (default: https://bestip.06151953.xyz)
 * @returns {Object} Request configuration
 */
export function createRequestConfig(env = {}) {
	const { UUID, SOCKS5, SOCKS5_RELAY, TROJAN_PASSWORD, PROXY_TIMEOUT, PROXY_FALLBACK, VLESS_OUTBOUND, BESTIP_URL } = env;
	const userID = UUID || defaultUserID;
	return {
		userID: userID,
		trojanPassword: TROJAN_PASSWORD || defaultTrojanPassword || userID,
		socks5Address: SOCKS5 || defaultSocks5Address,
		socks5Relay: SOCKS5_RELAY === 'true' || defaultSocks5Relay,
		proxyIP: null,
		proxyPort: null,
		// Proxy type: 'socks5' | 'http' | 'vless' | null
		proxyType: null,
		parsedProxyAddress: null,
		// Multi-proxy rotation settings
		proxyTimeout: PROXY_TIMEOUT ? parseInt(PROXY_TIMEOUT, 10) : defaultProxyTimeout,
		enableProxyFallback: PROXY_FALLBACK !== 'false' && defaultEnableProxyFallback,
		// VLESS outbound configuration
		vlessOutbound: VLESS_OUTBOUND || defaultVlessOutbound,
		parsedVlessOutbound: null,
		// bestIP endpoint base URL (trailing slash stripped)
		bestipUrl: (BESTIP_URL || defaultBestipUrl).replace(/\/+$/, '')
	};
}
