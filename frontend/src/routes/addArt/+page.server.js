import { API_BASE_URL } from '$env/static/private';

// TODO: implement with complete API endpoint
/*
export const actions = {
    default: async ({ request }) => {
        const formData = await request.formData()
        const uploadData = Object.fromEntries(formData)

        const response = await fetch(
        `${API_BASE_URL}/api/`, // replace with full path
        {
            method: 'POST',
            headers: {
                'Content-type': 'application/json',
            },
            body: JSON.stringify(uploadData)
        });

        if(!response.ok){
            return { success: false, message: 'Error adding artwork.'}
        }
        else {
            return { success: true, message: 'Artwork added successfully!'}
        }

    }
}
*/