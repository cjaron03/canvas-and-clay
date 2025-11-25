import { API_BASE_URL } from '$env/static/private';
import { error } from '@sveltejs/kit';
import { extractErrorMessage } from '$lib/utils/errorMessages';

export const load = async ({ params, fetch }) => {
  const { id } = params;

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/artists/${encodeURIComponent(id)}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    if (response.status === 404) {
      throw error(404, 'Artist not found.');
    }

    if (!response.ok) {
      const errorMessage = await extractErrorMessage(response, 'load artist details');
      throw error(response.status, errorMessage);
    }

    const artist = await response.json();

    // Gets artworks for the related artists from the GET /artworks endpoint
    const artworkParams = new URLSearchParams();
    artworkParams.set('artist_id', id);
    artworkParams.set('page', '1');
    artworkParams.set('per_page', '500');

    const artworksResponse = await fetch(
      `${API_BASE_URL}/api/artworks?${artworkParams.toString()}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    let artworks = [];
    let artworksError = null;
    if (artworksResponse.ok) {
      const artworksData = await artworksResponse.json();
      artworks = artworksData.artworks ?? [];
    } else {
      artworksError = await extractErrorMessage(
        artworksResponse,
        'load artworks for artist'
      );
    }

    return { artist, artworks, artworksError };
  } catch (err) {
    console.error('artist detail load failed:', err);
    if (err.status) {
      throw err;
    }
    const message =
      err instanceof Error ? `${err.message}.` : 'Failed to load artist.';
    throw error(500, message);
  }
};
