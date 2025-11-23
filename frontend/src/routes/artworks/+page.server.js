import { API_BASE_URL } from '$env/static/private';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ url, fetch }) => {
  const page = parseInt(url.searchParams.get('page') ?? '1', 10);
  const perPage = parseInt(url.searchParams.get('per_page') ?? '20', 10);
  const search = url.searchParams.get('search') ?? '';
  const artistId = url.searchParams.get('artist_id') ?? '';
  const medium = url.searchParams.get('medium') ?? '';
  const storageId = url.searchParams.get('storage_id') ?? '';
  const ordering = url.searchParams.get('ordering') ?? 'title_asc';

  try {
    // Build query string
    const params = new URLSearchParams();
    params.set('page', page.toString());
    params.set('per_page', perPage.toString());
    if (search) params.set('search', search);
    if (artistId) params.set('artist_id', artistId);
    if (medium) params.set('medium', medium);
    if (storageId) params.set('storage_id', storageId);
    if (ordering) params.set('ordering', ordering);

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
        filters: { search, artistId, medium, storageId, ordering },
        artists: [],
        artistsError: errorMessage,
        storage: [],
        storageError: errorMessage
      };
    }

    const data = await response.json();
    const artistsResponse = await fetch(`${API_BASE_URL}/api/artists_dropdown`, {
      headers: {
        accept: 'application/json'
      }
    });
    const storageResponse = await fetch(`${API_BASE_URL}/api/storage`, {
      headers: {
        accept: 'application/json'
      }
    });

    let artists = [];
    let artistsError = null;
    let storage = [];
    let storageError = null;
    if (artistsResponse.ok) {
      const artistsData = await artistsResponse.json();
      artists = artistsData.artists ?? [];
    } else {
      artistsError = await extractErrorMessage(artistsResponse, 'load artists list');
    }
    if (storageResponse.ok) {
      const storageData = await storageResponse.json();
      storage = storageData.storage ?? [];
    } else {
      storageError = await extractErrorMessage(storageResponse, 'load storage locations');
    }

    return {
      artworks: data.artworks ?? [],
      pagination: data.pagination ?? null,
      error: null,
      filters: { search, artistId, medium, storageId, ordering },
      artists,
      artistsError,
      storage,
      storageError
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
      filters: { search, artistId, medium, storageId, ordering },
      artists: [],
      artistsError: message,
      storage: [],
      storageError: message
    };
  }
};
