import { env as privateEnv } from '$env/dynamic/private';
import { PUBLIC_API_BASE_URL } from '$env/static/public';

const API_BASE_URL = privateEnv.API_BASE_URL || PUBLIC_API_BASE_URL || 'http://localhost:5001';

export const load = async ({ fetch }) => {
  try {
    // Fetch users with artist role for the user linking dropdown
    const response = await fetch(`${API_BASE_URL}/api/admin/console/users`, {
      headers: {
        accept: 'application/json'
      },
      credentials: 'include'
    });

    if (response.ok) {
      const data = await response.json();
      // Filter to only show users with artist role who aren't deleted
      const artistUsers = (data.users || []).filter(
        u => u.role === 'artist' && !u.deleted_at
      );
      return { users: artistUsers };
    }
  } catch (error) {
    console.error('Failed to fetch users for artist linking:', error);
  }

  // Return empty users array if fetch fails (dropdown will just be empty)
  return { users: [] };
};
