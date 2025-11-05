import { API_BASE_URL } from '$env/static/private';

// TODO: implement with complete API endpoint
/*
export const load = () => {
    const response = await fetch(
        `${API_BASE_URL}/api/`,
        {
            method: 'POST',
            headers: {
                accept: 'application'
            }
    }
    );
}
*/

// test form output
export const actions = {
    default: async ({ request }) => {
        const formData = await request.formData()
        console.log(formData)
    }
}