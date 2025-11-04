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
				}
			} catch (error) {
				console.error('Auth init failed:', error);
			}
		},

		// Login
		async login(email, password, remember = false) {
			let csrfToken;
			update((state) => {
				csrfToken = state.csrfToken;
				return state;
			});

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
				const error = await response.json().catch(() => ({ error: 'Login failed' }));
				throw new Error(error.error || `HTTP ${response.status}`);
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
			let csrfToken;
			update((state) => {
				csrfToken = state.csrfToken;
				return state;
			});

			try {
				await fetch(`${PUBLIC_API_BASE_URL}/auth/logout`, {
					method: 'POST',
					headers: {
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
				csrfToken
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
