import { API_BASE_URL } from '$env/static/private';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ url, fetch }) => {
  const page = parseInt(url.searchParams.get('page') ?? '1', 10);
  const perPage = parseInt(url.searchParams.get('per_page') ?? '20', 10);
  const search = url.searchParams.get('search') ?? '';
  const artistId = url.searchParams.get('artist_id') ?? '';
  const medium = url.searchParams.get('medium') ?? '';

  try {
    // Build query string
    const params = new URLSearchParams();
    params.set('page', page.toString());
    params.set('per_page', perPage.toString());
    if (search) params.set('search', search);
    if (artistId) params.set('artist_id', artistId);
    if (medium) params.set('medium', medium);

    const response = await fetch(
      `${API_BASE_URL}/api/artworks?${params.toString()}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    if (!response.ok) {
      const errorMessage = await extractErrorMessage(response, 'load artworks');
      return {
        artworks: [],
        pagination: null,
        error: errorMessage,
        filters: { search, artistId, medium }
      };
    }

    const data = await response.json();

    return {
      artworks: data.artworks ?? [],
      pagination: data.pagination ?? null,
      error: null,
      filters: { search, artistId, medium }
    };

  } catch (err) {
    console.error('artworks load failed:', err);
    const message = err instanceof Error 
      ? `${err.message}. Suggestion: Check your internet connection and try again.` 
      : 'Unexpected error while loading artworks. Suggestion: Refresh the page or try again later.';
    return {
      artworks: [],
      pagination: null,
      error: message,
      filters: { search, artistId, medium }
    };
  }
};
