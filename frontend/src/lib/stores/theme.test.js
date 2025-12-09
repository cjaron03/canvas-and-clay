import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';

// Mock $app/environment before importing the store
vi.mock('$app/environment', () => ({
	browser: true
}));

// Mock localStorage
const localStorageMock = (() => {
	let store = {};
	return {
		getItem: vi.fn((key) => store[key] || null),
		setItem: vi.fn((key, value) => {
			store[key] = value;
		}),
		removeItem: vi.fn((key) => {
			delete store[key];
		}),
		clear: vi.fn(() => {
			store = {};
		}),
		_getStore: () => store
	};
})();

// Mock document.documentElement
const documentMock = {
	setAttribute: vi.fn()
};

describe('theme store', () => {
	let theme;

	beforeEach(async () => {
		// Reset mocks
		localStorageMock.clear();
		vi.clearAllMocks();

		// Setup global mocks
		vi.stubGlobal('localStorage', localStorageMock);
		vi.stubGlobal('document', { documentElement: documentMock });

		// Reset module cache and reimport to get fresh store
		vi.resetModules();
		const module = await import('./theme.js');
		theme = module.theme;
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	describe('initial state', () => {
		it('should default to dark theme when localStorage is empty', () => {
			const value = get(theme);
			expect(value).toBe('dark');
		});

		it('should read light theme from localStorage', async () => {
			localStorageMock.setItem('theme', 'light');
			vi.resetModules();
			const module = await import('./theme.js');
			const freshTheme = module.theme;
			expect(get(freshTheme)).toBe('light');
		});

		it('should default to dark for invalid localStorage values', async () => {
			localStorageMock.setItem('theme', 'invalid');
			vi.resetModules();
			const module = await import('./theme.js');
			const freshTheme = module.theme;
			expect(get(freshTheme)).toBe('dark');
		});
	});

	describe('toggle', () => {
		it('should toggle from dark to light', () => {
			// Start with dark
			expect(get(theme)).toBe('dark');

			theme.toggle();

			expect(get(theme)).toBe('light');
			expect(localStorageMock.setItem).toHaveBeenCalledWith('theme', 'light');
			expect(documentMock.setAttribute).toHaveBeenCalledWith('data-theme', 'light');
		});

		it('should toggle from light to dark', async () => {
			localStorageMock.setItem('theme', 'light');
			vi.resetModules();
			const module = await import('./theme.js');
			const freshTheme = module.theme;

			expect(get(freshTheme)).toBe('light');

			freshTheme.toggle();

			expect(get(freshTheme)).toBe('dark');
			expect(localStorageMock.setItem).toHaveBeenCalledWith('theme', 'dark');
		});

		it('should toggle multiple times correctly', () => {
			expect(get(theme)).toBe('dark');

			theme.toggle(); // -> light
			expect(get(theme)).toBe('light');

			theme.toggle(); // -> dark
			expect(get(theme)).toBe('dark');

			theme.toggle(); // -> light
			expect(get(theme)).toBe('light');
		});
	});

	describe('setTheme', () => {
		it('should set theme to dark', () => {
			theme.setTheme('dark');

			expect(get(theme)).toBe('dark');
			expect(localStorageMock.setItem).toHaveBeenCalledWith('theme', 'dark');
			expect(documentMock.setAttribute).toHaveBeenCalledWith('data-theme', 'dark');
		});

		it('should set theme to light', () => {
			theme.setTheme('light');

			expect(get(theme)).toBe('light');
			expect(localStorageMock.setItem).toHaveBeenCalledWith('theme', 'light');
			expect(documentMock.setAttribute).toHaveBeenCalledWith('data-theme', 'light');
		});

		it('should ignore invalid theme values', () => {
			const initialValue = get(theme);

			theme.setTheme('invalid');

			expect(get(theme)).toBe(initialValue);
		});

		it('should ignore null theme value', () => {
			const initialValue = get(theme);

			theme.setTheme(null);

			expect(get(theme)).toBe(initialValue);
		});

		it('should ignore undefined theme value', () => {
			const initialValue = get(theme);

			theme.setTheme(undefined);

			expect(get(theme)).toBe(initialValue);
		});
	});

	describe('init', () => {
		it('should set data-theme attribute on document', () => {
			theme.init();

			expect(documentMock.setAttribute).toHaveBeenCalledWith('data-theme', expect.any(String));
		});

		it('should apply current theme from store', () => {
			theme.setTheme('light');
			vi.clearAllMocks();

			theme.init();

			expect(documentMock.setAttribute).toHaveBeenCalledWith('data-theme', 'light');
		});
	});

	describe('subscription', () => {
		it('should notify subscribers on toggle', () => {
			const values = [];
			const unsubscribe = theme.subscribe((value) => {
				values.push(value);
			});

			theme.toggle();
			theme.toggle();

			// Initial value + 2 toggles
			expect(values.length).toBeGreaterThanOrEqual(3);
			unsubscribe();
		});

		it('should notify subscribers on setTheme', () => {
			const values = [];
			const unsubscribe = theme.subscribe((value) => {
				values.push(value);
			});

			theme.setTheme('light');
			theme.setTheme('dark');

			expect(values).toContain('light');
			expect(values).toContain('dark');
			unsubscribe();
		});
	});
});
