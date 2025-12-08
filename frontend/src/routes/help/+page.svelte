<script>
  import { theme } from '$lib/stores/theme';
  
  let searchQuery = '';
  let activeCategory = 'all';

  const categories = [
    { id: 'basics', name: 'Basics & Account', icon: 'user' },
    { id: 'gallery', name: 'Viewing Art', icon: 'image' },
    { id: 'artists', name: 'For Artists', icon: 'palette' },
    { id: 'troubleshooting', name: 'Troubleshooting', icon: 'tool' }
  ];

  const articles = [
    {
      title: 'Creating an Account',
      category: 'basics',
      content: 'To join Canvas and Clay, click "Create account" on the login page. You will need a valid email address and a strong password. Once registered, you can access additional features like saving favorites or, if approved, uploading your own art.'
    },
    {
      title: 'Signing In & Security',
      category: 'basics',
      content: 'Access your account using your email and password. You can stay signed in by checking "Remember me". For security, we recommend using a unique password. You can manage your security settings in the "Account" tab.'
    },
    {
      title: 'Browsing the Gallery',
      category: 'gallery',
      content: 'The Gallery page displays all public artworks. You can filter by artist, medium, or search for specific titles. Click on any artwork to view it in high resolution and see details about the piece.'
    },
    {
      title: 'Uploading Artwork',
      category: 'artists',
      content: 'Artist accounts can upload images via the "Uploads" tab. Ensure your images are high-quality (JPG or PNG) and include a title and description. You can toggle visibility of your works at any time.'
    },
    {
      title: 'Managing Your Portfolio',
      category: 'artists',
      content: 'Navigate to "My Artworks" to see a list of everything you have uploaded. From here, you can edit details, delete works, or change their public visibility status.'
    },
    {
      title: 'Resetting Your Password',
      category: 'troubleshooting',
      content: 'If you forget your password, click "Forgot password?" on the login screen. Enter your email to request a reset code. An administrator will review the request and send you a code to set a new password.'
    },
    {
      title: 'Updating Profile Information',
      category: 'basics',
      content: 'Go to your Account page to update your email address or change your password. You can also view your account activity and role status here.'
    }
  ];

  $: filteredArticles = articles.filter(article => {
    const matchesSearch = article.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          article.content.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = activeCategory === 'all' || article.category === activeCategory;
    return matchesSearch && matchesCategory;
  });
</script>

<div class="help-page">
  <div class="help-header">
    <h1>How can we help you?</h1>
    <div class="search-box">
      <svg class="search-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input 
        type="text" 
        placeholder="Describe your issue" 
        bind:value={searchQuery}
      />
    </div>
  </div>

  <div class="help-container">
    <div class="category-nav">
      <button 
        class="cat-btn" 
        class:active={activeCategory === 'all'} 
        on:click={() => activeCategory = 'all'}
      >
        All
      </button>
      {#each categories as cat}
        <button 
          class="cat-btn" 
          class:active={activeCategory === cat.id} 
          on:click={() => activeCategory = cat.id}
        >
          {cat.name}
        </button>
      {/each}
    </div>

    <div class="articles-grid">
      {#each filteredArticles as article}
        <div class="article-card">
          <h3>{article.title}</h3>
          <p>{article.content}</p>
          <div class="article-footer">
            <span class="category-tag">{categories.find(c => c.id === article.category)?.name}</span>
          </div>
        </div>
      {:else}
        <div class="no-results">
          <p>No articles found matching "{searchQuery}"</p>
        </div>
      {/each}
    </div>

    <div class="contact-section">
      <h2>Still need help?</h2>
      <p>If you can't find the answer you're looking for, please contact the administration team.</p>
      <a href="mailto:support@canvasandclay.example.com" class="contact-btn">Contact Support</a>
    </div>
  </div>
</div>

<style>
  .help-page {
    min-height: calc(100vh - 64px);
    background: var(--bg-primary);
    animation: pageEnter 0.3s ease-out;
  }

  @keyframes pageEnter {
    from {
      opacity: 0;
      transform: translateY(12px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .help-header {
    background: var(--bg-secondary);
    padding: 4rem 2rem;
    text-align: center;
    border-bottom: 1px solid var(--border-color);
  }

  .help-header h1 {
    font-size: 2rem;
    color: var(--text-primary);
    margin-bottom: 2rem;
    font-weight: 600;
  }

  .search-box {
    max-width: 600px;
    margin: 0 auto;
    position: relative;
  }

  .search-box input {
    width: 100%;
    height: 48px;
    padding: 0 16px 0 48px;
    border-radius: 24px;
    border: 1px solid var(--border-color);
    font-size: 1rem;
    background: var(--bg-primary);
    color: var(--text-primary);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
    transition: all 0.15s ease;
    box-sizing: border-box;
  }

  .search-box input:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
  }

  .search-icon {
    position: absolute;
    left: 16px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-secondary);
  }

  .help-container {
    max-width: 1000px;
    margin: 0 auto;
    padding: 2rem;
  }

  .category-nav {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 2rem;
    flex-wrap: wrap;
    justify-content: center;
  }

  .cat-btn {
    padding: 0 20px;
    height: 36px;
    border-radius: 18px;
    border: 1px solid var(--border-color);
    background: var(--bg-primary);
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
  }

  .cat-btn:hover {
    background: rgba(0, 122, 255, 0.08);
    border-color: var(--accent-color);
    color: var(--accent-color);
  }

  .cat-btn.active {
    background: var(--accent-color);
    color: white;
    border-color: var(--accent-color);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .articles-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.5rem;
    margin-bottom: 4rem;
  }

  .article-card {
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    transition: all 0.15s ease;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .article-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 24px rgba(0,0,0,0.1);
    border-color: var(--accent-color);
  }

  .article-card h3 {
    margin: 0 0 0.75rem 0;
    color: var(--text-primary);
    font-size: 1.1rem;
    font-weight: 500;
  }

  .article-card p {
    color: var(--text-secondary);
    font-size: 0.9rem;
    line-height: 1.6;
    margin: 0 0 1rem 0;
  }

  .article-footer {
    margin-top: auto;
  }

  .category-tag {
    font-size: 0.75rem;
    color: var(--accent-color);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 600;
  }

  .no-results {
    grid-column: 1 / -1;
    text-align: center;
    padding: 3rem;
    color: var(--text-secondary);
  }

  .contact-section {
    text-align: center;
    padding: 3rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .contact-section h2 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-weight: 600;
  }

  .contact-section p {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
  }

  .contact-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 24px;
    height: 44px;
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: 22px;
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 600;
    transition: all 0.15s ease;
  }

  .contact-btn:hover {
    background: rgba(0, 122, 255, 0.08);
    border-color: var(--accent-color);
    transform: translateY(-2px);
  }

  @media (max-width: 600px) {
    .help-header {
      padding: 2rem 1rem;
    }
    
    .help-header h1 {
      font-size: 1.5rem;
    }

    .help-container {
      padding: 1rem;
    }
    
    .articles-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
