import { PUBLIC_API_BASE_URL } from '$env/static/public';

export const load = async ({ url, fetch }) => {
  const rawQuery = url.searchParams.get('q') ?? '';
  const searchTerm = rawQuery.trim();

  if (!searchTerm) {
    return { q: rawQuery, results: [], error: null };
  }

  try {
    const response = await fetch(
      `${PUBLIC_API_BASE_URL}/api/search?q=${encodeURIComponent(searchTerm)}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    if (!response.ok) {
      return { q: rawQuery, results: [], error: `Search failed: HTTP ${response.status}` };
    }

    const data = await response.json();
    const items = Array.isArray(data?.items) ? data.items : [];

    return { q: rawQuery, results: items, error: null };
  } catch (err) {
      console.error('search load failed for', searchTerm, err);
      const message = err instanceof Error ? err.message : 'Unexpected error while performing search';

    return { q: rawQuery, results: [], error: message };
  }
};
