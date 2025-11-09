import { API_BASE_URL } from '$env/static/private';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ url, fetch }) => {
  const rawQuery = url.searchParams.get('q') ?? '';
  const searchTerm = rawQuery.trim();

  if (!searchTerm) {
    return { q: rawQuery, results: [], error: null };
  }

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/search?q=${encodeURIComponent(searchTerm)}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    if (!response.ok) {
      const errorMessage = await extractErrorMessage(response, 'perform search');
      return { q: rawQuery, results: [], error: errorMessage };
    }

    const data = await response.json();
    const items = Array.isArray(data?.items) ? data.items : [];

    return { q: rawQuery, results: items, error: null };
    
  } catch (err) {
    console.error('search load failed for', searchTerm, err);
    const message = err instanceof Error 
      ? `${err.message}. Suggestion: Check your internet connection and try again.` 
      : 'Unexpected error while performing search. Suggestion: Refresh the page or try again later.';
    return { q: rawQuery, results: [], error: message };
  }
};
