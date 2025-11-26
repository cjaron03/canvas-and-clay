import { env as privateEnv } from '$env/dynamic/private';
import { PUBLIC_API_BASE_URL } from '$env/static/public';
import { error } from '@sveltejs/kit';
import { extractErrorMessage } from '$lib/utils/errorMessages';

const API_BASE_URL = privateEnv.API_BASE_URL || PUBLIC_API_BASE_URL || 'http://localhost:5000';

export const load = async ({ params, fetch }) => {
  const { id } = params;

  try {
    // Fetch artwork, artists, and storage locations in parallel
    const [artworkResponse, artistsResponse, storageResponse] = await Promise.all([
      fetch(`${API_BASE_URL}/api/artworks/${encodeURIComponent(id)}`, {
        headers: {
          accept: 'application/json'
        }
      }),
      fetch(`${API_BASE_URL}/api/artists`, {
        headers: {
          accept: 'application/json'
        }
      }),
      fetch(`${API_BASE_URL}/api/storage`, {
        headers: {
          accept: 'application/json'
        }
      })
    ]);

    if (artworkResponse.status === 404) {
      throw error(404, 'Artwork not found. Suggestion: Check the artwork ID or browse artworks to find what you\'re looking for.');
    }

    if (!artworkResponse.ok) {
      const errorMessage = await extractErrorMessage(artworkResponse, 'load artwork details');
      throw error(artworkResponse.status, errorMessage);
    }

    const artwork = await artworkResponse.json();

    let artists = [];
    let storage = [];
    let loadError = null;

    if (artistsResponse.ok) {
      const artistsData = await artistsResponse.json();
      artists = artistsData.artists || [];
    } else {
      loadError = await extractErrorMessage(artistsResponse, 'load artists list');
    }

    if (storageResponse.ok) {
      const storageData = await storageResponse.json();
      storage = storageData.storage || [];
    } else {
      const storageError = await extractErrorMessage(storageResponse, 'load storage locations');
      loadError = loadError || storageError;
    }

    return {
      artwork,
      artists,
      storage,
      error: loadError
    };
  } catch (err) {
    console.error('Failed to load edit form data:', err);
    if (err.status) {
      throw err;
    }
    const message = err instanceof Error 
      ? `${err.message}. Suggestion: Check your internet connection and refresh the page.` 
      : 'Failed to load edit form data. Suggestion: Refresh the page or try again later.';
    throw error(500, message);
  }
};
