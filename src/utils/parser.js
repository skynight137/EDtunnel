/**
 * Parser utilities for addresses and parameters
 */

import { proxyIPs } from '../config/defaults.js';

/**
 * Parses a VLESS URL into configuration object
 * Format: vless://uuid@host:port?type=ws&security=tls&path=/path&sni=host#name
 * @param {string} url - VLESS URL string
 * @returns {{
 *   uuid: string,
 *   address: string,
 *   port: number,
 *   streamSettings: {
 *     network: string,
 *     security: string,
 *     wsSettings?: { path: string, headers?: Object },
 *     tlsSettings?: { serverName: string }
 *   }
 * }|null} Parsed configuration or null if invalid
 */
export function parseVlessUrl(url) {
	if (!url || !url.startsWith('vless://')) {
		return null;
	}

	try {
		// Remove 'vless://' prefix and fragment
		const urlWithoutProtocol = url.slice(8).split('#')[0];

		// Split by @ to get uuid and rest
		const atIndex = urlWithoutProtocol.indexOf('@');
		if (atIndex === -1) return null;

		const uuid = urlWithoutProtocol.slice(0, atIndex);
		const rest = urlWithoutProtocol.slice(atIndex + 1);

		// Parse host:port and query string
		const [hostPort, queryString] = rest.split('?');

		// Handle IPv6 addresses in brackets
		let address, port;
		if (hostPort.startsWith('[')) {
			// IPv6 format: [::1]:port
			const bracketEnd = hostPort.indexOf(']');
			if (bracketEnd === -1) return null;
			address = hostPort.slice(1, bracketEnd);
			const portPart = hostPort.slice(bracketEnd + 1);
			if (portPart.startsWith(':')) {
				port = parseInt(portPart.slice(1), 10);
			} else {
				port = 443; // default port
			}
		} else {
			// IPv4 or domain format
			const colonIndex = hostPort.lastIndexOf(':');
			if (colonIndex === -1) {
				address = hostPort;
				port = 443; // default port
			} else {
				address = hostPort.slice(0, colonIndex);
				port = parseInt(hostPort.slice(colonIndex + 1), 10);
			}
		}

		if (isNaN(port)) port = 443;

		// Parse query parameters
		const params = {};
		if (queryString) {
			queryString.split('&').forEach((pair) => {
				const [key, value] = pair.split('=');
				if (key) {
					params[decodeURIComponent(key)] = decodeURIComponent(value || '');
				}
			});
		}

		// Build stream settings
		const streamSettings = {
			network: params.type || 'ws',
			security: params.security || 'none',
		};

		if (streamSettings.network === 'ws') {
			streamSettings.wsSettings = {
				path: params.path || '/',
			};
			if (params.host) {
				streamSettings.wsSettings.headers = { Host: params.host };
			}
		}

		if (streamSettings.security === 'tls') {
			streamSettings.tlsSettings = {
				serverName: params.sni || params.host || address,
			};
		}

		return { uuid, address, port, streamSettings };
	} catch (e) {
		console.error('[VLESS] Failed to parse URL:', e);
		return null;
	}
}

/**
 * Parses SOCKS5 address string into components.
 * @param {string} address - SOCKS5 address string (format: 'username:password@host:port' or 'host:port')
 * @returns {{username: string|undefined, password: string|undefined, hostname: string, port: number}} Parsed address information
 * @throws {Error} If address format is invalid
 */
export function socks5AddressParser(address) {
	let [latter, former] = address.split("@").reverse();
	let username, password, hostname, port;
	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('Invalid SOCKS address format');
		}
		[username, password] = formers;
	}
	const latters = latter.split(":");
	port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('Invalid SOCKS address format');
	}
	hostname = latters.join(":");
	const regex = /^\[.*\]$/;
	if (hostname.includes(":") && !regex.test(hostname)) {
		throw new Error('Invalid SOCKS address format');
	}
	return {
		username,
		password,
		hostname,
		port,
	};
}

/**
 * Handles proxy configuration and returns standardized proxy settings.
 * @param {string} PROXYIP - Proxy IP configuration from environment
 * @returns {{ip: string, port: string}} Standardized proxy configuration
 */
export function handleProxyConfig(PROXYIP) {
	if (PROXYIP) {
		const proxyAddresses = PROXYIP.split(',').map(addr => addr.trim());
		const selectedProxy = selectRandomAddress(proxyAddresses);
		const [ip, port = '443'] = selectedProxy.split(':');
		return { ip, port };
	} else {
		// Use default from proxyIPs
		const defaultProxy = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
		const port = defaultProxy.includes(':') ? defaultProxy.split(':')[1] : '443';
		const ip = defaultProxy.split(':')[0];
		return { ip, port };
	}
}

/**
 * Selects a random address from a comma-separated string or array of addresses.
 * @param {string|string[]} addresses - Comma-separated string or array of addresses
 * @returns {string} Selected address
 */
export function selectRandomAddress(addresses) {
	const addressArray = typeof addresses === 'string' ?
		addresses.split(',').map(addr => addr.trim()) :
		addresses;
	return addressArray[Math.floor(Math.random() * addressArray.length)];
}


/**
 * NOTE: URL/path parameter parsing (parseEncodedQueryParams, parsePathProxyParams,
 * decodeProxyAddress) was removed — this fork selects the per-request outbound
 * via X-Relay-* headers (parseHeaderProxyParams below), not URL parameters.
 * Parses header-based relay parameters.
 * Header version of the per-request proxy selection: the outbound is chosen
 * per request via X-Relay-* headers instead of URL parameters, so the URL
 * stays the target URL (and the cache key) and the outbound never appears
 * in a shareable/logged URL. Headers override environment variables.
 * UUID is intentionally never read from a header (environment only).
 * @param {Request} request - Incoming request
 * @returns {{proxyip: string|null, socks5: string|null, http: string|null, vless: string|null, globalProxy: boolean}} Parsed parameters
 */
export function parseHeaderProxyParams(request) {
	const headers = request.headers;
	const result = {
		proxyip: headers.get('X-Relay-ProxyIP') || null,
		socks5: headers.get('X-Relay-Socks5') || null,
		http: headers.get('X-Relay-HTTP') || null,
		vless: headers.get('X-Relay-Vless') || null,
		globalProxy: false
	};
	const global = headers.get('X-Relay-Global');
	if (global && (global.toLowerCase() === 'true' || global === '1')) {
		result.globalProxy = true;
	}
	return result;
}
