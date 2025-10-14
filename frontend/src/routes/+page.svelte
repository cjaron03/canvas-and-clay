<h1>welcome to the frontend</h1>
<p>so cool</p>


<script>
    async function testAPI() {
      const response = await fetch('http://localhost:5001/api/hello');
      const data = await response.json();
      alert(JSON.stringify(data, null, 2));
    }
  </script>
  
  <h1>Canvas and Clay</h1>
  <button on:click={testAPI}>Test API</button>