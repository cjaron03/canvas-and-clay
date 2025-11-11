import { writable } from 'svelte/store';
import { browser } from '$app/environment';

// Theme store
function createThemeStore() {
	// Get initial theme from localStorage or default to dark
	const getInitialTheme = () => {
		if (!browser) return 'dark';
		const stored = localStorage.getItem('theme');
		return stored === 'light' ? 'light' : 'dark';
	};

	const { subscribe, set, update } = writable(getInitialTheme());

	return {
		subscribe,

		// Toggle between light and dark
		toggle() {
			update((current) => {
				const newTheme = current === 'dark' ? 'light' : 'dark';
				if (browser) {
					localStorage.setItem('theme', newTheme);
					document.documentElement.setAttribute('data-theme', newTheme);
				}
				return newTheme;
			});
		},

		// Set specific theme
		setTheme(theme) {
			if (theme !== 'light' && theme !== 'dark') return;
			set(theme);
			if (browser) {
				localStorage.setItem('theme', theme);
				document.documentElement.setAttribute('data-theme', theme);
			}
		},

		// Initialize theme on mount
		init() {
			if (browser) {
				const theme = getInitialTheme();
				document.documentElement.setAttribute('data-theme', theme);
			}
		}
	};
}

export const theme = createThemeStore();

