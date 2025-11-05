import { API_BASE_URL } from '$env/static/private';
import { error } from '@sveltejs/kit';

export const load = async ({ params, fetch }) => {
  const { id } = params;

  try {
    const response = await fetch(
      `${API_BASE_URL}/api/artworks/${encodeURIComponent(id)}`,
      {
        headers: {
          accept: 'application/json'
        }
      }
    );

    if (response.status === 404) {
      throw error(404, 'Artwork not found');
    }

    if (!response.ok) {
      throw error(response.status, `Failed to load artwork: HTTP ${response.status}`);
    }

    const artwork = await response.json();
    return { artwork };

  } catch (err) {
    console.error('artwork detail load failed:', err);
    if (err.status) {
      throw err;
    }
    throw error(500, err instanceof Error ? err.message : 'Failed to load artwork');
  }
};
