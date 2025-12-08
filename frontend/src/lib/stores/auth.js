import { writable } from 'svelte/store';
import { goto } from '$app/navigation';
import { PUBLIC_API_BASE_URL } from '$env/static/public';

// User state store with multi-account support
function createAuthStore() {
	const { subscribe, set, update } = writable({
		user: null,
		isAuthenticated: false,
		csrfToken: null,
		accounts: [], // All authenticated accounts
		activeAccountId: null // Currently active account ID
	});

	let initPromise = null; // Track ongoing initialization to prevent duplicate calls

	// Helper to get current CSRF token
	const getCsrfToken = async (currentToken) => {
		if (currentToken) return currentToken;

		try {
			const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
				credentials: 'include'
			});
			if (csrfResponse.ok) {
				const csrfData = await csrfResponse.json();
				return csrfData.csrf_token;
			}
		} catch (error) {
			console.error('Failed to fetch CSRF token:', error);
		}
		return null;
	};

	// Helper to handle API errors
	const handleApiError = async (response) => {
		let errorData;
		const contentType = response.headers.get('content-type') || '';
		try {
			if (contentType.includes('application/json')) {
				errorData = await response.json();
			} else {
				const text = await response.text();
				if (response.status === 400) {
					if (text.includes('CSRF') || text.includes('csrf')) {
						errorData = { error: 'CSRF token missing or invalid. Please refresh the page and try again.' };
					} else {
						errorData = { error: `Bad request (HTTP 400). Please check your input and try again.` };
					}
				} else {
					errorData = { error: `Server error (HTTP ${response.status})` };
				}
			}
		} catch {
			errorData = { error: `Failed to parse server response (HTTP ${response.status})` };
		}

		if (response.status === 429) {
			const error = new Error(errorData.error || 'Too many attempts. Please wait before trying again.');
			error.rateLimited = true;
			error.retryAfter = response.headers.get('Retry-After');
			throw error;
		}

		let errorMessage = errorData.error || 'Request failed';
		if (response.status === 401) {
			errorMessage = errorData.error || 'Invalid credentials. Please try again.';
		} else if (response.status === 403) {
			errorMessage = errorData.error || 'Access denied.';
		} else if (response.status === 409) {
			errorMessage = errorData.error || 'Conflict - resource already exists.';
		} else if (response.status >= 500) {
			errorMessage = 'Server error. Please try again later.';
		}

		const error = new Error(errorMessage);
		error.statusCode = response.status;
		throw error;
	};

	return {
		subscribe,

		// Initialize: fetch CSRF token, check auth status, and load accounts
		async init() {
			if (initPromise) {
				return initPromise;
			}

			initPromise = (async () => {
				try {
					// Get CSRF token
					const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
						credentials: 'include'
					});
					let csrfToken = null;
					if (csrfResponse.ok) {
						const data = await csrfResponse.json();
						csrfToken = data.csrf_token;
						update((state) => ({ ...state, csrfToken }));
					}

					// Check if already logged in
					const meResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/me`, {
						credentials: 'include'
					});

					if (meResponse.ok) {
						const meData = await meResponse.json();

						// Fetch accounts list
						const accountsResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/accounts`, {
							credentials: 'include'
						});

						let accounts = [];
						let activeAccountId = meData.user.id;
						if (accountsResponse.ok) {
							const accountsData = await accountsResponse.json();
							accounts = accountsData.accounts || [];
							// Find the active account
							const active = accounts.find((a) => a.is_active);
							if (active) activeAccountId = active.id;
						}

						update((state) => ({
							user: meData.user,
							isAuthenticated: true,
							csrfToken: state.csrfToken,
							accounts,
							activeAccountId
						}));
					} else {
						if (meResponse.status !== 401) {
							console.warn('Auth check failed:', meResponse.status);
						}
						set({
							user: null,
							isAuthenticated: false,
							csrfToken: null,
							accounts: [],
							activeAccountId: null
						});
					}
				} catch (error) {
					console.error('Auth init failed:', error);
					set({
						user: null,
						isAuthenticated: false,
						csrfToken: null,
						accounts: [],
						activeAccountId: null
					});
				} finally {
					initPromise = null;
				}
			})();

			return initPromise;
		},

		// Login (primary account or replace current session)
		async login(email, password, remember = false) {
			let csrfToken;
			update((state) => {
				csrfToken = state.csrfToken;
				return state;
			});

			csrfToken = await getCsrfToken(csrfToken);
			if (!csrfToken) {
				throw new Error('CSRF token is required. Please refresh the page and try again.');
			}
			update((state) => ({ ...state, csrfToken }));

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
				await handleApiError(response);
			}

			const data = await response.json();
			set({
				user: data.user,
				isAuthenticated: true,
				csrfToken,
				accounts: data.accounts || [{ ...data.user, is_active: true }],
				activeAccountId: data.user.id
			});

			return data;
		},

		// Add another account without logging out
		async addAccount(email, password, remember = false) {
			let csrfToken;
			update((state) => {
				csrfToken = state.csrfToken;
				return state;
			});

			csrfToken = await getCsrfToken(csrfToken);
			if (!csrfToken) {
				throw new Error('CSRF token is required. Please refresh the page and try again.');
			}
			update((state) => ({ ...state, csrfToken }));

			const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/add-account`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': csrfToken
				},
				credentials: 'include',
				body: JSON.stringify({ email, password, remember })
			});

			if (!response.ok) {
				await handleApiError(response);
			}

			const data = await response.json();
			update((state) => ({
				...state,
				accounts: data.accounts || state.accounts
			}));

			return data;
		},

		// Switch to another authenticated account
		async switchAccount(accountId) {
			let csrfToken;
			update((state) => {
				csrfToken = state.csrfToken;
				return state;
			});

			csrfToken = await getCsrfToken(csrfToken);
			if (!csrfToken) {
				throw new Error('CSRF token is required. Please refresh the page and try again.');
			}

			const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/switch-account`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': csrfToken
				},
				credentials: 'include',
				body: JSON.stringify({ account_id: accountId })
			});

			if (!response.ok) {
				await handleApiError(response);
			}

			const data = await response.json();
			update((state) => ({
				...state,
				user: data.user,
				accounts: data.accounts || state.accounts,
				activeAccountId: data.user.id
			}));

			return data;
		},

		// Remove an account from the session
		async removeAccount(accountId) {
			let csrfToken;
			update((state) => {
				csrfToken = state.csrfToken;
				return state;
			});

			csrfToken = await getCsrfToken(csrfToken);
			if (!csrfToken) {
				throw new Error('CSRF token is required. Please refresh the page and try again.');
			}

			const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/remove-account`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': csrfToken
				},
				credentials: 'include',
				body: JSON.stringify({ account_id: accountId })
			});

			if (!response.ok) {
				await handleApiError(response);
			}

			const data = await response.json();

			// If no accounts left, we're logged out
			if (!data.accounts || data.accounts.length === 0) {
				set({
					user: null,
					isAuthenticated: false,
					csrfToken: null,
					accounts: [],
					activeAccountId: null
				});
				goto('/login');
				return data;
			}

			// Update with new user if we switched
			update((state) => ({
				...state,
				user: data.user || state.user,
				accounts: data.accounts,
				activeAccountId: data.user?.id || state.activeAccountId
			}));

			return data;
		},

		// Refresh accounts list from server
		async refreshAccounts() {
			try {
				const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/accounts`, {
					credentials: 'include'
				});

				if (response.ok) {
					const data = await response.json();
					update((state) => ({
						...state,
						accounts: data.accounts || []
					}));
					return data.accounts;
				}
			} catch (error) {
				console.error('Failed to refresh accounts:', error);
			}
			return [];
		},

		// Logout ALL accounts
		async logout() {
			try {
				const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
					credentials: 'include'
				});
				let csrfToken = null;
				if (csrfResponse.ok) {
					const data = await csrfResponse.json();
					csrfToken = data.csrf_token;
				}

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

			set({
				user: null,
				isAuthenticated: false,
				csrfToken: null,
				accounts: [],
				activeAccountId: null
			});

			goto('/login?logout=success');
		},

		// Update user data (e.g., after email change)
		updateUser(userData) {
			update((state) => ({
				...state,
				user: { ...state.user, ...userData }
			}));
		},

		// Clear state (for use after 401 errors)
		clear() {
			update((state) => ({
				...state,
				user: null,
				isAuthenticated: false,
				accounts: [],
				activeAccountId: null
			}));
		}
	};
}

export const auth = createAuthStore();
