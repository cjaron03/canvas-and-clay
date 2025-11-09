import { writable } from 'svelte/store';
import { goto } from '$app/navigation';
import { PUBLIC_API_BASE_URL } from '$env/static/public';

// User state store
function createAuthStore() {
	const { subscribe, set, update } = writable({
		user: null,
		isAuthenticated: false,
		csrfToken: null
	});

	return {
		subscribe,

		// Initialize: fetch CSRF token and check authentication status
		async init() {
			try {
				// Get CSRF token
				const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
					credentials: 'include'
				});
				if (csrfResponse.ok) {
					const data = await csrfResponse.json();
					update((state) => ({ ...state, csrfToken: data.csrf_token }));
				}

				// Check if already logged in
				const meResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/me`, {
					credentials: 'include'
				});
				if (meResponse.ok) {
					const data = await meResponse.json();
					set({
						user: data.user,
						isAuthenticated: true,
						csrfToken: data.csrf_token || null
					});
				} else {
					// Explicitly clear auth state if not authenticated
					set({
						user: null,
						isAuthenticated: false,
						csrfToken: null
					});
				}
			} catch (error) {
				console.error('Auth init failed:', error);
				// Clear auth state on error
				set({
					user: null,
					isAuthenticated: false,
					csrfToken: null
				});
			}
		},

		// Login
		async login(email, password, remember = false) {
			// Ensure we have a CSRF token before login
			let csrfToken;
			update((state) => {
				csrfToken = state.csrfToken;
				return state;
			});

			// Fetch CSRF token if we don't have one
			if (!csrfToken) {
				try {
					const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
						credentials: 'include'
					});
					if (csrfResponse.ok) {
						const csrfData = await csrfResponse.json();
						csrfToken = csrfData.csrf_token;
						update((state) => ({ ...state, csrfToken: csrfToken }));
					}
				} catch (error) {
					throw new Error('Failed to fetch CSRF token. Please refresh the page and try again.');
				}
			}

			if (!csrfToken) {
				throw new Error('CSRF token is required. Please refresh the page and try again.');
			}

			const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/login`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': csrfToken
				},
				credentials: 'include',
				body: JSON.stringify({ email, password, remember })
			});

			if (!response.ok) {
				let errorData;
				const contentType = response.headers.get('content-type') || '';
				try {
					if (contentType.includes('application/json')) {
						errorData = await response.json();
					} else {
						// Handle non-JSON responses (e.g., CSRF errors might return HTML)
						const text = await response.text();
						if (response.status === 400) {
							if (text.includes('CSRF') || text.includes('csrf')) {
								errorData = { error: 'CSRF token missing or invalid. Please refresh the page and try again.' };
							} else if (text.includes('The CSRF token is missing')) {
								errorData = { error: 'CSRF token is missing. Please refresh the page and try again.' };
							} else if (text.includes('The CSRF token has expired')) {
								errorData = { error: 'CSRF token has expired. Please refresh the page and try again.' };
							} else {
								// Try to extract error message from HTML if possible
								const errorMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i) || text.match(/error[^>]*>([^<]+)/i);
								if (errorMatch) {
									errorData = { error: errorMatch[1].trim() };
								} else {
									errorData = { error: `Bad request (HTTP 400). Please check your input and try again.` };
								}
							}
						} else {
							errorData = { error: `Server error (HTTP ${response.status})` };
						}
					}
				} catch {
					errorData = { error: `Failed to parse server response (HTTP ${response.status})` };
				}

				if (response.status === 429) {
					const error = new Error(errorData.error || 'Too many login attempts. Please wait before trying again.');
					error.rateLimited = true;
					error.retryAfter = response.headers.get('Retry-After');
					throw error;
				}

				// Create descriptive error messages based on status code
				let errorMessage = errorData.error || 'Login failed';
				
				if (response.status === 400) {
					// Validation errors - use the backend's error message
					errorMessage = errorData.error || 'Invalid request. Please check your email and password.';
				} else if (response.status === 401) {
					errorMessage = errorData.error || 'Invalid email or password. Please try again.';
				} else if (response.status === 403) {
					errorMessage = errorData.error || 'Access denied. Your account may be locked or disabled.';
				} else if (response.status >= 500) {
					errorMessage = 'Server error. Please try again later.';
				} else {
					errorMessage = errorData.error || `Login failed (HTTP ${response.status})`;
				}

				const error = new Error(errorMessage);
				error.statusCode = response.status;
				throw error;
			}

			const data = await response.json();
			set({
				user: data.user,
				isAuthenticated: true,
				csrfToken
			});

			return data;
		},

		// Logout
		async logout() {
			try {
				// Get a fresh CSRF token before logout
				const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
					credentials: 'include'
				});
				let csrfToken = null;
				if (csrfResponse.ok) {
					const data = await csrfResponse.json();
					csrfToken = data.csrf_token;
				}

				// Attempt logout with fresh token
				await fetch(`${PUBLIC_API_BASE_URL}/auth/logout`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-CSRFToken': csrfToken
					},
					credentials: 'include'
				});
			} catch (error) {
				console.error('Logout failed:', error);
			}

			// Clear auth state regardless of logout success
			set({
				user: null,
				isAuthenticated: false,
				csrfToken: null
			});

			goto('/login');
		},

		// Clear state (for use after 401 errors)
		clear() {
			update((state) => ({
				...state,
				user: null,
				isAuthenticated: false
			}));
		}
	};
}

export const auth = createAuthStore();
