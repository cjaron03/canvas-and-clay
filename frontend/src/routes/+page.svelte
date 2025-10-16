<script>
  import { env } from '$app/environment';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  const testAPI = async () => {
    const apiUrl = `${PUBLIC_API_BASE_URL}/api/hello`;
    const response = await fetch(apiUrl);
    const data = await response.json();
    alert(JSON.stringify(data, null, 2));
  };
</script>

<h1>Canvas and Clay</h1>
<p>Welcome to the frontend</p>
<button on:click={testAPI}>Test API</button>