import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';

// Mock environment variables
vi.mock('$env/static/public', () => ({
	PUBLIC_API_BASE_URL: 'http://localhost:5001'
}));

// Mock SvelteKit navigation
vi.mock('$app/navigation', () => ({
	goto: vi.fn()
}));

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('auth store', () => {
	let auth;
	let goto;

	const mockUser = {
		id: 1,
		email: 'test@example.com',
		role: 'guest'
	};

	const mockAdminUser = {
		id: 2,
		email: 'admin@example.com',
		role: 'admin'
	};

	// Helper to create mock fetch responses
	const mockResponse = (data, status = 200, headers = {}) => ({
		ok: status >= 200 && status < 300,
		status,
		headers: {
			get: (key) => headers[key.toLowerCase()] || null
		},
		json: vi.fn().mockResolvedValue(data),
		text: vi.fn().mockResolvedValue(JSON.stringify(data))
	});

	beforeEach(async () => {
		vi.clearAllMocks();
		mockFetch.mockReset();

		// Reset module cache to get fresh store
		vi.resetModules();
		const module = await import('./auth.js');
		auth = module.auth;

		const navModule = await import('$app/navigation');
		goto = navModule.goto;
	});

	afterEach(() => {
		vi.clearAllMocks();
	});

	describe('initial state', () => {
		it('should start with user as null', () => {
			const state = get(auth);
			expect(state.user).toBeNull();
		});

		it('should start with isAuthenticated as false', () => {
			const state = get(auth);
			expect(state.isAuthenticated).toBe(false);
		});

		it('should start with empty accounts array', () => {
			const state = get(auth);
			expect(state.accounts).toEqual([]);
		});

		it('should start with csrfToken as null', () => {
			const state = get(auth);
			expect(state.csrfToken).toBeNull();
		});

		it('should start with activeAccountId as null', () => {
			const state = get(auth);
			expect(state.activeAccountId).toBeNull();
		});
	});

	describe('init', () => {
		it('should fetch CSRF token on init', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'test-token' }))
				.mockResolvedValueOnce(mockResponse({}, 401));

			await auth.init();

			expect(mockFetch).toHaveBeenCalledWith(
				'http://localhost:5001/auth/csrf-token',
				expect.objectContaining({ credentials: 'include' })
			);
		});

		it('should check auth status via /auth/me', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'test-token' }))
				.mockResolvedValueOnce(mockResponse({}, 401));

			await auth.init();

			expect(mockFetch).toHaveBeenCalledWith(
				'http://localhost:5001/auth/me',
				expect.objectContaining({ credentials: 'include' })
			);
		});

		it('should set user when already authenticated', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'test-token' }))
				.mockResolvedValueOnce(mockResponse({ user: mockUser }))
				.mockResolvedValueOnce(
					mockResponse({ accounts: [{ ...mockUser, is_active: true }] })
				);

			await auth.init();

			const state = get(auth);
			expect(state.user).toEqual(mockUser);
			expect(state.isAuthenticated).toBe(true);
		});

		it('should remain logged out when not authenticated', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'test-token' }))
				.mockResolvedValueOnce(mockResponse({}, 401));

			await auth.init();

			const state = get(auth);
			expect(state.user).toBeNull();
			expect(state.isAuthenticated).toBe(false);
		});

		it('should prevent duplicate init calls', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'test-token' }))
				.mockResolvedValueOnce(mockResponse({}, 401));

			// Call init twice simultaneously
			const promise1 = auth.init();
			const promise2 = auth.init();

			await Promise.all([promise1, promise2]);

			// Should only make 2 calls total (csrf + me), not 4
			expect(mockFetch).toHaveBeenCalledTimes(2);
		});
	});

	describe('login', () => {
		beforeEach(() => {
			// Setup CSRF token fetch
			mockFetch.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }));
		});

		it('should successfully login and set user', async () => {
			mockFetch.mockResolvedValueOnce(
				mockResponse({
					user: mockUser,
					accounts: [{ ...mockUser, is_active: true }]
				})
			);

			await auth.login('test@example.com', 'password123');

			const state = get(auth);
			expect(state.user).toEqual(mockUser);
			expect(state.isAuthenticated).toBe(true);
			expect(state.activeAccountId).toBe(mockUser.id);
		});

		it('should include CSRF token in login request', async () => {
			mockFetch.mockResolvedValueOnce(mockResponse({ user: mockUser }));

			await auth.login('test@example.com', 'password123');

			expect(mockFetch).toHaveBeenLastCalledWith(
				'http://localhost:5001/auth/login',
				expect.objectContaining({
					headers: expect.objectContaining({
						'X-CSRFToken': 'csrf-token'
					})
				})
			);
		});

		it('should throw error on invalid credentials', async () => {
			mockFetch.mockResolvedValueOnce(
				mockResponse({ error: 'Invalid credentials' }, 401, {
					'content-type': 'application/json'
				})
			);

			await expect(auth.login('test@example.com', 'wrongpass')).rejects.toThrow();
		});

		it('should handle rate limiting with rateLimited flag', async () => {
			mockFetch.mockResolvedValueOnce(
				mockResponse({ error: 'Too many attempts' }, 429, {
					'content-type': 'application/json',
					'retry-after': '60'
				})
			);

			try {
				await auth.login('test@example.com', 'password');
				expect.fail('Should have thrown');
			} catch (error) {
				expect(error.rateLimited).toBe(true);
				expect(error.retryAfter).toBe('60');
			}
		});

		it('should pass remember flag to API', async () => {
			mockFetch.mockResolvedValueOnce(mockResponse({ user: mockUser }));

			await auth.login('test@example.com', 'password', true);

			const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
			const body = JSON.parse(lastCall[1].body);
			expect(body.remember).toBe(true);
		});
	});

	describe('logout', () => {
		it('should clear all auth state on logout', async () => {
			// First login
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(mockResponse({ user: mockUser }));

			await auth.login('test@example.com', 'password');
			expect(get(auth).isAuthenticated).toBe(true);

			// Then logout
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'new-token' }))
				.mockResolvedValueOnce(mockResponse({ success: true }));

			await auth.logout();

			const state = get(auth);
			expect(state.user).toBeNull();
			expect(state.isAuthenticated).toBe(false);
			expect(state.accounts).toEqual([]);
			expect(state.activeAccountId).toBeNull();
		});

		it('should redirect to login page after logout', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(mockResponse({ success: true }));

			await auth.logout();

			expect(goto).toHaveBeenCalledWith('/login?logout=success');
		});

		it('should clear state even if logout API call fails', async () => {
			// Setup authenticated state
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(mockResponse({ user: mockUser }));
			await auth.login('test@example.com', 'password');

			// Logout with API failure
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockRejectedValueOnce(new Error('Network error'));

			await auth.logout();

			const state = get(auth);
			expect(state.isAuthenticated).toBe(false);
			expect(state.user).toBeNull();
		});
	});

	describe('addAccount', () => {
		it('should add account to accounts array', async () => {
			// Setup initial login
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(
					mockResponse({
						user: mockUser,
						accounts: [{ ...mockUser, is_active: true }]
					})
				);

			await auth.login('test@example.com', 'password');

			// Add another account
			mockFetch.mockResolvedValueOnce(
				mockResponse({
					accounts: [
						{ ...mockUser, is_active: true },
						{ ...mockAdminUser, is_active: false }
					]
				})
			);

			await auth.addAccount('admin@example.com', 'adminpass');

			const state = get(auth);
			expect(state.accounts).toHaveLength(2);
		});
	});

	describe('switchAccount', () => {
		it('should switch active user', async () => {
			// Setup with multiple accounts
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(
					mockResponse({
						user: mockUser,
						accounts: [
							{ ...mockUser, is_active: true },
							{ ...mockAdminUser, is_active: false }
						]
					})
				);

			await auth.login('test@example.com', 'password');

			// Switch to admin
			mockFetch.mockResolvedValueOnce(
				mockResponse({
					user: mockAdminUser,
					accounts: [
						{ ...mockUser, is_active: false },
						{ ...mockAdminUser, is_active: true }
					]
				})
			);

			await auth.switchAccount(mockAdminUser.id);

			const state = get(auth);
			expect(state.user).toEqual(mockAdminUser);
			expect(state.activeAccountId).toBe(mockAdminUser.id);
		});
	});

	describe('removeAccount', () => {
		it('should remove account from accounts array', async () => {
			// Setup with multiple accounts
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(
					mockResponse({
						user: mockUser,
						accounts: [
							{ ...mockUser, is_active: true },
							{ ...mockAdminUser, is_active: false }
						]
					})
				);

			await auth.login('test@example.com', 'password');

			// Remove admin account
			mockFetch.mockResolvedValueOnce(
				mockResponse({
					user: mockUser,
					accounts: [{ ...mockUser, is_active: true }]
				})
			);

			await auth.removeAccount(mockAdminUser.id);

			const state = get(auth);
			expect(state.accounts).toHaveLength(1);
			expect(state.accounts[0].id).toBe(mockUser.id);
		});

		it('should logout when removing last account', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(
					mockResponse({
						user: mockUser,
						accounts: [{ ...mockUser, is_active: true }]
					})
				);

			await auth.login('test@example.com', 'password');

			// Remove last account
			mockFetch.mockResolvedValueOnce(
				mockResponse({
					accounts: []
				})
			);

			await auth.removeAccount(mockUser.id);

			const state = get(auth);
			expect(state.isAuthenticated).toBe(false);
			expect(state.user).toBeNull();
			expect(goto).toHaveBeenCalledWith('/login');
		});
	});

	describe('updateUser', () => {
		it('should update user data in store', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(mockResponse({ user: mockUser }));

			await auth.login('test@example.com', 'password');

			auth.updateUser({ email: 'newemail@example.com' });

			const state = get(auth);
			expect(state.user.email).toBe('newemail@example.com');
			expect(state.user.id).toBe(mockUser.id); // Other fields preserved
		});
	});

	describe('clear', () => {
		it('should clear user state without calling API', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(mockResponse({ user: mockUser }));

			await auth.login('test@example.com', 'password');
			const fetchCountBeforeClear = mockFetch.mock.calls.length;

			auth.clear();

			const state = get(auth);
			expect(state.user).toBeNull();
			expect(state.isAuthenticated).toBe(false);
			expect(state.accounts).toEqual([]);
			// Should not have made additional API calls
			expect(mockFetch.mock.calls.length).toBe(fetchCountBeforeClear);
		});
	});

	describe('refreshAccounts', () => {
		it('should fetch fresh accounts list from server', async () => {
			mockFetch
				.mockResolvedValueOnce(mockResponse({ csrf_token: 'csrf-token' }))
				.mockResolvedValueOnce(mockResponse({ user: mockUser }));

			await auth.login('test@example.com', 'password');

			mockFetch.mockResolvedValueOnce(
				mockResponse({
					accounts: [
						{ ...mockUser, is_active: true },
						{ ...mockAdminUser, is_active: false }
					]
				})
			);

			const accounts = await auth.refreshAccounts();

			expect(accounts).toHaveLength(2);
			expect(mockFetch).toHaveBeenLastCalledWith(
				'http://localhost:5001/auth/accounts',
				expect.objectContaining({ credentials: 'include' })
			);
		});

		it('should return empty array on error', async () => {
			mockFetch.mockRejectedValueOnce(new Error('Network error'));

			const accounts = await auth.refreshAccounts();

			expect(accounts).toEqual([]);
		});
	});
});
