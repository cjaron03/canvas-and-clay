import { env as privateEnv } from '$env/dynamic/private';
import { PUBLIC_API_BASE_URL } from '$env/static/public';
import { error } from '@sveltejs/kit';
import { extractErrorMessage } from '$lib/utils/errorMessages';

const API_BASE_URL = privateEnv.API_BASE_URL || PUBLIC_API_BASE_URL || 'http://localhost:5000';

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
      throw error(404, 'Artist not found. Suggestion: Verify the artist ID and try again.');
    }

    if (!response.ok) {
      const errorMessage = await extractErrorMessage(response, 'load artist details');
      throw error(response.status, errorMessage);
    }

    const artist = await response.json();

    let photo = null;
    try {
      const photoResponse = await fetch(
        `${API_BASE_URL}/api/artists/${encodeURIComponent(id)}/photos`,
        {
          method: 'GET',
          headers: { accept: 'application/json' }
        }
      );

      if (photoResponse.ok) {
        const payload = await photoResponse.json();
        photo = payload.photo ?? null;
      } else if (photoResponse.status !== 404) {
        console.warn('Failed to load artist photo metadata:', await photoResponse.text());
      }
    } catch (photoErr) {
      console.warn('Error loading artist photo metadata:', photoErr);
    }

    return { artist, photo };
  } catch (err) {
    console.error('Failed to load artist edit data:', err);
    if (err.status) {
      throw err;
    }
    const message = err instanceof Error
      ? `${err.message}. Suggestion: Check your internet connection and refresh the page.`
      : 'Failed to load artist edit form data. Suggestion: Refresh the page or try again later.';
    throw error(500, message);
  }
};
