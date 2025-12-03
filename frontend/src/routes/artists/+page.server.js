import { env as privateEnv } from '$env/dynamic/private';
import { PUBLIC_API_BASE_URL } from '$env/static/public';
import { extractErrorMessage } from '$lib/utils/errorMessages';

const API_BASE_URL = privateEnv.API_BASE_URL || PUBLIC_API_BASE_URL || 'http://localhost:5000';

// Stores the GET request parameters from the URL into constants
export const load = async ({ url, fetch }) => {
  const page = parseInt(url.searchParams.get('page') ?? '1', 10);
  const perPage = parseInt(url.searchParams.get('per_page') ?? '24', 10);
  const search = url.searchParams.get('search') ?? '';
  const storageId = url.searchParams.get('storage_id') ?? '';
  const ordering = url.searchParams.get('ordering') ?? 'name_asc';

  try {
    // Rebuilds query string cleanly
    const params = new URLSearchParams();
    params.set('page', page.toString());
    params.set('per_page', perPage.toString());
    if (search) params.set('search', search);
    if (storageId) params.set('storage_id', storageId);
    if (ordering) params.set('ordering', ordering);
    // TODO add: owned_only (bool): Implements views by account permissions

    const response = await fetch(
      `${API_BASE_URL}/api/artists?${params.toString()}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    // Error handling for bad response from the /artists GET call
    // Includes fields for storage to align with all the fields +page.svelte expects 
    // even though /storage has not been called yet
    if (!response.ok) {
      const errorMessage = await extractErrorMessage(response, 'load artists');
      return {
        artists: [],
        pagination: null,
        error: errorMessage,
        filters: { search, storageId, ordering },
        storage: [],
        storageError: null
      };
    }

    const data = await response.json();

    // Fetches all storage options to build the storage dropdown
    const storageResponse = await fetch(`${API_BASE_URL}/api/storage`, {
      headers: {
        accept: 'application/json'
      }
    });

    let storage = [];
    let storageError = null;
    if (storageResponse.ok) {
      const storageData = await storageResponse.json();
      storage = storageData.storage ?? [];
    } else {
      storageError = await extractErrorMessage(storageResponse, 'load locations');
    }

    return {
      artists: data.artists ?? [],
      pagination: data.pagination ?? null,
      error: null,
      filters: { search, storageId, ordering },
      storage,
      storageError
    };
  } catch (err) {
    console.error('artists load failed:', err);
    const message = err instanceof Error
      ? `${err.message}.`
      : 'Unexpected error while loading artists.';
    return {
      artists: [],
      pagination: null,
      error: message,
      filters: { search, storageId, ordering },
      storage: [],
      storageError: message
    };
  }
};
