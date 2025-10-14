<script>
  const testAPI = async () => {
    const response = await fetch('http://localhost:5001/api/hello');
    const data = await response.json();
    alert(JSON.stringify(data, null, 2));
  };
</script>

<h1>Canvas and Clay</h1>
<p>Welcome to the frontend</p>
<button on:click={testAPI}>Test API</button>