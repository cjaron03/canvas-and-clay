import { env as privateEnv } from '$env/dynamic/private';
import { PUBLIC_API_BASE_URL } from '$env/static/public';

const API_BASE_URL = privateEnv.API_BASE_URL || PUBLIC_API_BASE_URL || 'http://localhost:5001';

export const load = async ({ fetch }) => {
    try {
        const response = await fetch(
            `${API_BASE_URL}/api/legal-pages/privacy_policy`,
            {
                headers: {
                    accept: 'application/json'
                }
            }
        );

        if (response.ok) {
            const data = await response.json();
            return {
                content: data,
                error: null
            };
        } else {
            // If not found, return null to use fallback static content
            return {
                content: null,
                error: null
            };
        }
    } catch (err) {
        console.error('Failed to load privacy policy:', err);
        return {
            content: null,
            error: null
        };
    }
};
