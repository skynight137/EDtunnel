/**
 * Main request handler and routing
 */

import { createRequestConfig, defaultUserID, proxyIPs } from '../config/defaults.js';
import { handleDefaultPath } from './http.js';
import { protocolOverWSHandler } from './websocket.js';
import { getConfig } from '../generators/config-page.js';
import { genSub, genTrojanSub } from '../generators/subscription.js';
import { handleProxyConfig, socks5AddressParser, selectRandomAddress, parseHeaderProxyParams, parseVlessUrl } from '../utils/parser.js';
import { isValidUUID } from '../utils/validation.js';

// Validate default user ID at startup
if (!isValidUUID(defaultUserID)) {
	throw new Error('uuid is not valid');
}

/**
 * Main request handler for the Cloudflare Worker.
 * Processes incoming requests and routes them appropriately.
 * @param {import("@cloudflare/workers-types").Request} request - The incoming request object
 * @param {Object} env - Environment variables containing configuration
 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx - Execution context
 * @param {Function} connect - Cloudflare socket connect function
 * @returns {Promise<Response>} Response object
 */
export async function handleRequest(request, env, ctx, connect) {
	try {
		const { UUID, PROXYIP, SOCKS5, SOCKS5_RELAY, TROJAN_PASSWORD } = env;
		// Fail closed: never fall back to the public default UUID (it is in
		// this repo, so anyone can look it up). A Worker without UUID set
		// must not serve traffic.
		if (!UUID) {
			throw new Error('UUID environment variable is required');
		}
		const url = new URL(request.url);

		// Create request-specific configuration
		const requestConfig = createRequestConfig(env);

		// Header-based relay parameters (X-Relay-*).
		// The per-request outbound is chosen via headers, not URL parameters,
		// so the URL stays the target URL (and the cache key) and the outbound
		// never appears in a shareable/logged URL. Headers override env vars.
		// UUID is intentionally never read from a header (environment only).
		const headerParams = parseHeaderProxyParams(request);
		let headerPROXYIP = headerParams.proxyip;
		let headerSOCKS5 = headerParams.socks5;
		const enableGlobalProxy = headerParams.globalProxy;
		let headerHTTP = headerParams.http;

		// Validate proxyip format
		if (headerPROXYIP) {
			const proxyPattern = /^([a-zA-Z0-9][-a-zA-Z0-9.]*(\.[a-zA-Z0-9][-a-zA-Z0-9.]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:]+\]):\d{1,5}$/;
			const proxyAddresses = headerPROXYIP.split(',').map(addr => addr.trim());
			const isValid = proxyAddresses.every(addr => proxyPattern.test(addr));
			if (!isValid) {
				// Do not log the raw header value (log injection; it may
				// also carry credentials in the socks5 case).
				console.warn('Invalid X-Relay-ProxyIP format; ignoring header');
				headerPROXYIP = null;
			}
		}

		// Validate socks5 format
		if (headerSOCKS5) {
			const socks5Pattern = /^(([^:@]+:[^:@]+@)?[a-zA-Z0-9][-a-zA-Z0-9.]*(\.[a-zA-Z0-9][-a-zA-Z0-9.]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}$/;
			const socks5Addresses = headerSOCKS5.split(',').map(addr => addr.trim());
			const isValid = socks5Addresses.every(addr => socks5Pattern.test(addr));
			if (!isValid) {
				// Do not log the raw header value (log injection; it may
				// carry proxy credentials).
				console.warn('Invalid X-Relay-Socks5 format; ignoring header');
				headerSOCKS5 = null;
			}
		}

		// Validate HTTP proxy format (same shape as SOCKS5: [user:pass@]host:port)
		if (headerHTTP) {
			const httpPattern = /^(([^:@]+:[^:@]+@)?[a-zA-Z0-9][-a-zA-Z0-9.]*(\.[a-zA-Z0-9][-a-zA-Z0-9.]*)+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}$/;
			const httpAddresses = headerHTTP.split(',').map(addr => addr.trim());
			const isValid = httpAddresses.every(addr => httpPattern.test(addr));
			if (!isValid) {
				// Do not log the raw header value (log injection; it may
				// carry proxy credentials).
				console.warn('Invalid X-Relay-HTTP format; ignoring header');
				headerHTTP = null;
			}
		}

		// Apply header parameters to request config
		requestConfig.socks5Address = headerSOCKS5 || requestConfig.socks5Address;
		requestConfig.globalProxy = enableGlobalProxy || requestConfig.socks5Relay;

		// Log only non-sensitive flags. Never log userID (the UUID) or
		// socks5Address (it may contain proxy user:pass) — both are
		// credentials and must not appear in Worker logs.
		console.log('Config params:', { globalProxy: requestConfig.globalProxy, hasProxy: !!headerPROXYIP, hasSocks5: !!requestConfig.socks5Address });

		// Handle proxy configuration
		const proxyConfig = handleProxyConfig(headerPROXYIP || PROXYIP);
		requestConfig.proxyIP = proxyConfig.ip;
		requestConfig.proxyPort = proxyConfig.port;

		// Log final proxy settings
		console.log('Using proxy:', requestConfig.proxyIP, requestConfig.proxyPort);

		// Parse VLESS outbound configuration (header > environment variable)
		let headerVLESS = headerParams.vless;
		if (headerVLESS || requestConfig.vlessOutbound) {
			try {
				const vlessUrl = headerVLESS || requestConfig.vlessOutbound;
				const parsed = parseVlessUrl(vlessUrl);
				if (parsed) {
					requestConfig.parsedVlessOutbound = parsed;
					requestConfig.proxyType = 'vless';
					// Use globalProxy flag from the X-Relay-Global header
					console.log('VLESS outbound configured:', parsed.address, parsed.port);
				}
			} catch (err) {
				console.log('VLESS outbound parse error:', err.toString());
			}
		}

		// Parse proxy configuration (VLESS > HTTP > SOCKS5)
		if (requestConfig.proxyType !== 'vless') {
			if (headerHTTP) {
				try {
					const selectedProxy = selectRandomAddress(headerHTTP);
					requestConfig.parsedProxyAddress = socks5AddressParser(selectedProxy);
					requestConfig.proxyType = 'http';
				} catch (err) {
					console.log('HTTP proxy parse error:', err.toString());
				}
			} else if (requestConfig.socks5Address) {
				try {
					const selectedProxy = selectRandomAddress(requestConfig.socks5Address);
					requestConfig.parsedProxyAddress = socks5AddressParser(selectedProxy);
					requestConfig.proxyType = 'socks5';
				} catch (err) {
					console.log('SOCKS5 proxy parse error:', err.toString());
				}
			}
		}

		const userIDs = requestConfig.userID.includes(',') ? requestConfig.userID.split(',').map(id => id.trim()) : [requestConfig.userID];
		const host = request.headers.get('Host');
		const requestedPath = url.pathname.substring(1); // Remove leading slash
		const matchingUserID = userIDs.length === 1 ?
			(requestedPath === userIDs[0] ||
				requestedPath === `sub/${userIDs[0]}` ||
				requestedPath === `bestip/${userIDs[0]}` ||
				requestedPath === `trojan/${userIDs[0]}` ? userIDs[0] : null) :
			userIDs.find(id => {
				const patterns = [id, `sub/${id}`, `bestip/${id}`, `trojan/${id}`];
				return patterns.some(pattern => requestedPath.startsWith(pattern));
			});

		// Non-WebSocket requests
		if (request.headers.get('Upgrade') !== 'websocket') {
			if (url.pathname === '/cf') {
				return new Response(JSON.stringify(request.cf, null, 4), {
					status: 200,
					headers: { "Content-Type": "application/json;charset=utf-8" },
				});
			}

			if (matchingUserID) {
				if (url.pathname === `/${matchingUserID}` || url.pathname === `/sub/${matchingUserID}`) {
					const isSubscription = url.pathname.startsWith('/sub/');
					// Priority: Header > environment variable > default
					const proxyAddresses = headerPROXYIP
						? headerPROXYIP.split(',').map(addr => addr.trim())
						: (PROXYIP ? PROXYIP.split(',').map(addr => addr.trim()) : proxyIPs);
					// Get Trojan password (priority: env > userID)
					const trojanPassword = TROJAN_PASSWORD || matchingUserID;
					const content = isSubscription ?
						genSub(matchingUserID, host, proxyAddresses, trojanPassword) :
						getConfig(matchingUserID, host, proxyAddresses, trojanPassword);

					return new Response(content, {
						status: 200,
						headers: {
							"Content-Type": isSubscription ?
								"text/plain;charset=utf-8" :
								"text/html; charset=utf-8"
						},
					});
				} else if (url.pathname === `/trojan/${matchingUserID}`) {
					// Trojan-only subscription
					const proxyAddresses = headerPROXYIP
						? headerPROXYIP.split(',').map(addr => addr.trim())
						: (PROXYIP ? PROXYIP.split(',').map(addr => addr.trim()) : proxyIPs);
					const trojanPassword = TROJAN_PASSWORD || matchingUserID;
					const content = genTrojanSub(trojanPassword, host, proxyAddresses);

					return new Response(content, {
						status: 200,
						headers: { "Content-Type": "text/plain;charset=utf-8" },
					});
				} else if (url.pathname === `/bestip/${matchingUserID}`) {
					// Forward only a fixed, non-sensitive User-Agent. Never
					// forward the incoming headers: they may carry X-Relay-*
					// proxy credentials (and any Cookie/Authorization) to
					// this third-party host. The endpoint is configurable
					// via the BESTIP_URL env var (default: the public
					// bestip.06151953.xyz) so a self-hosted bestIP on a
					// different machine can be pointed at.
					return fetch(`${requestConfig.bestipUrl}/auto?host=${host}&uuid=${matchingUserID}&path=/`, { headers: { 'User-Agent': 'EDtunnel' } });
				}
			}
			return handleDefaultPath(url, request);
		} else {
			// WebSocket upgrade request
			return await protocolOverWSHandler(request, requestConfig, connect);
		}
	} catch (err) {
		return new Response(err.toString());
	}
}
