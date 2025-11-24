<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { auth } from '$lib/stores/auth';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  export let data;

  let deleteConfirm = false;
  let deleteError = null;
  let isDeleting = false;
  let selectedPhoto = null;
  let modalElement;

  const getThumbnailUrl = (path) => {
    if (!path) return null;
    if (path.startsWith('http')) return path;
    return `${PUBLIC_API_BASE_URL}${path}`;
  };
 
 









 
</script>

<div class="container">
  <a href="/artists" class="back-link">← Back to Artists</a>
  <h1>Artist {params.id}</h1>
  <p>Artist details coming soon.</p>
</div>

<style>
  .container {
    max-width: 800px;
    margin: 0 auto;
    padding: 2rem 1rem;
  }

  .back-link {
    display: inline-block;
    margin-bottom: 1rem;
    text-decoration: none;
    color: var(--accent-color);
  }

  .back-link:hover {
    text-decoration: underline;
  }

  h1 {
    margin-top: 0;
    color: var(--text-primary);
  }

  p {
    color: var(--text-secondary);
  }
</style>
