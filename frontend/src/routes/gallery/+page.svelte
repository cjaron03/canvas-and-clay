<script>
    import { PUBLIC_API_BASE_URL } from '$env/static/public';
    import { auth } from '$lib/stores/auth';
    import { fade } from 'svelte/transition';
    import { onMount, onDestroy } from 'svelte';

    export let data;

    let currArtIndex = 0;

    const getThumbnailUrl = (thumbnail) => {
        if (!thumbnail) return null;
        if (thumbnail.startsWith('http')) return thumbnail;
        return `${PUBLIC_API_BASE_URL}${thumbnail}`;
    };

    const nextArtwork = () => {
        currArtIndex = (currArtIndex + 1) % data.artworks.length;
    };
    const prevArtwork = () => {
        currArtIndex = (currArtIndex - 1 + data.artworks.length) % data.artworks.length;
    };

    const handleKeydown = (e) => {
        if (e.key === 'ArrowRight') nextArtwork();
        if (e.key === 'ArrowLeft') prevArtwork();
    };

    onMount(() => {
        window.addEventListener('keydown', handleKeydown);
    });

    onDestroy(() => {
        if (typeof window !== 'undefined') {
            window.removeEventListener('keydown', handleKeydown);
        }
    });
</script>

<div class="gallery-viewport">
    {#if data.artworks && data.artworks.length > 0}
        <button class="nav-btn prev" on:click={prevArtwork} aria-label="Previous artwork">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
        </button>

        <div class="gallery-content">
            <div class="image-container">
                {#key currArtIndex}
                    <div class="image-wrapper" in:fade={{ duration: 300 }}>
                        {#if data.artworks[currArtIndex].primary_photo?.url}
                            <img 
                                src={getThumbnailUrl(data.artworks[currArtIndex].primary_photo.url)}
                                alt={data.artworks[currArtIndex].title}
                                class="artwork-image"
                            />
                        {:else if data.artworks[currArtIndex].primary_photo?.thumbnail_url}
                            <img 
                                src={getThumbnailUrl(data.artworks[currArtIndex].primary_photo.thumbnail_url)}
                                alt={data.artworks[currArtIndex].title}
                                class="artwork-image"
                            />
                        {:else}
                            <div class="no-image">
                                <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
                            </div>
                        {/if}
                    </div>
                {/key}
            </div>

            <div class="info-bar">
                <div class="text-content">
                    <h1>{data.artworks[currArtIndex].title}</h1>
                    <p class="artist-name">
                        {data.artworks[currArtIndex].artist.name}
                        {#if $auth.isAuthenticated && data.artworks[currArtIndex].artist.email}
                            <span class="artist-email">({data.artworks[currArtIndex].artist.email})</span>
                        {/if}
                    </p>
                </div>
                
                {#if $auth.isAuthenticated && $auth.user?.role === 'admin'}
                    <a href="/artworks/{data.artworks[currArtIndex].id}/edit" class="edit-btn" title="Edit Artwork">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    </a>
                {/if}
            </div>
        </div>

        <button class="nav-btn next" on:click={nextArtwork} aria-label="Next artwork">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </button>
    {:else}
        <div class="empty-state">
            <p>No artworks available for display{data.error ? `: ${data.error}` : ''}</p>
        </div>
    {/if}
</div>

<style>
    .gallery-viewport {
        display: flex;
        align-items: center;
        justify-content: center;
        height: calc(100vh - 64px); /* Full height minus nav */
        width: 100%;
        position: relative;
        background: var(--bg-primary);
        overflow: hidden;
    }

    .gallery-content {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        width: 100%;
        height: 100%;
        padding: 0; /* Remove all padding here */
    }

    .image-container {
        flex: 1;
        width: 100%;
        height: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
        min-height: 0;
        padding: 0; /* Zero padding */
    }

    .image-wrapper {
        width: 100%;
        height: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        position: absolute;
        inset: 0;
    }

    .artwork-image {
        max-width: 100%;
        max-height: 100%; /* Fill container, not viewport */
        width: auto;
        height: auto;
        object-fit: contain;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.15);
        border-radius: 4px;
    }

    .no-image {
        width: 100%;
        height: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        background: var(--bg-secondary);
        border-radius: 8px;
        color: var(--text-tertiary);
    }

    .info-bar {
        width: 100%;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        padding: 1rem 2rem; /* Padding for text */
        background: var(--bg-primary); /* Ensure background covers image if it overlaps */
        border-top: 1px solid var(--border-color);
        z-index: 20;
    }

    .text-content h1 {
        font-size: 1.75rem;
        font-weight: 600;
        margin: 0 0 0.25rem 0;
        color: var(--text-primary);
    }

    .artist-name {
        font-size: 1rem;
        color: var(--text-secondary);
        margin: 0;
        font-weight: 500;
    }

    .artist-email {
        font-size: 0.875rem;
        opacity: 0.7;
        font-weight: normal;
        margin-left: 0.5rem;
    }

    .nav-btn {
        position: absolute;
        top: 50%;
        transform: translateY(-50%);
        background: transparent;
        border: none;
        color: var(--text-secondary);
        cursor: pointer;
        padding: 1rem;
        transition: all 0.2s;
        z-index: 30;
        border-radius: 50%;
    }

    .nav-btn:hover {
        background: rgba(0, 0, 0, 0.05);
        color: var(--text-primary);
        transform: translateY(-50%) scale(1.1);
    }

    .nav-btn.prev { left: 0.5rem; }
    .nav-btn.next { right: 0.5rem; }

    .edit-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 0.5rem;
        color: var(--text-secondary);
        border-radius: 6px;
        transition: all 0.2s;
    }

    .edit-btn:hover {
        background: var(--bg-tertiary);
        color: var(--accent-color);
    }

    .empty-state {
        color: var(--text-secondary);
    }

    @media (max-width: 768px) {
        .image-container {
            padding: 0.5rem;
        }
        
        .image-wrapper {
            padding: 0.5rem;
        }

        .nav-btn {
            padding: 0.5rem;
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(4px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .nav-btn.prev { left: 0.5rem; }
        .nav-btn.next { right: 0.5rem; }
        
        .info-bar {
            padding: 1rem;
        }
    }
</style>
