<script>
  import { theme } from '$lib/stores/theme';
  import { auth } from '$lib/stores/auth';

  let searchQuery = '';
  let activeCategory = 'all';
  let expandedFaq = null;

  // Contact form state
  let contactName = '';
  let contactEmail = '';
  let contactMessage = '';
  let contactSuccess = false;

  const categories = [
    { id: 'basics', name: 'Basics & Account', icon: 'user' },
    { id: 'gallery', name: 'Viewing Art', icon: 'image' },
    { id: 'artists', name: 'For Artists', icon: 'palette' },
    { id: 'troubleshooting', name: 'Troubleshooting', icon: 'tool' }
  ];

  const articles = [
    // Basics & Account
    {
      title: 'Creating an Account',
      category: 'basics',
      content: 'To join Canvas and Clay, click "Create account" on the login page. You will need a valid email address and a strong password. Once registered, you can access additional features like saving favorites or, if approved, uploading your own art.'
    },
    {
      title: 'Signing In & Security',
      category: 'basics',
      content: 'Access your account using your email and password. For security, we recommend using a unique password. You can manage your security settings in the Account page.'
    },
    {
      title: 'Updating Profile Information',
      category: 'basics',
      content: 'Go to your Account page to update your email address or change your password. You can also view your account activity and role status here.'
    },
    {
      title: 'Account Roles Explained',
      category: 'basics',
      content: 'Canvas and Clay has three user roles: Guests can browse the public gallery without signing in. Artists can upload and manage their own artwork. Admins have full access to manage users, artworks, and platform settings.'
    },
    // Viewing Art
    {
      title: 'Browsing the Gallery',
      category: 'gallery',
      content: 'The Gallery page displays all public artworks. You can filter by artist, medium, or search for specific titles. Click on any artwork to view it in high resolution and see details about the piece.'
    },
    {
      title: 'Search Tips',
      category: 'gallery',
      content: 'Use the search bar to find artworks by title, artist name, or keywords. You can also search by Photo ID (8-character code like "2510C590") to find specific images. Try combining terms for more precise results.'
    },
    // For Artists
    {
      title: 'Uploading Artwork',
      category: 'artists',
      content: 'Artist accounts can upload images via the "Uploads" tab. Ensure your images are high-quality and include a title and description. You can toggle visibility of your works at any time.'
    },
    {
      title: 'Image Upload Requirements',
      category: 'artists',
      content: 'Supported formats: JPEG, PNG, WebP, and AVIF. Maximum file size is 10MB per image. For best results, upload high-resolution images (at least 1920px on the longest side). EXIF metadata is automatically stripped for privacy.'
    },
    {
      title: 'Managing Your Portfolio',
      category: 'artists',
      content: 'Navigate to "My Artworks" to see a list of everything you have uploaded. From here, you can edit details, delete works, or change their public visibility status.'
    },
    {
      title: 'Storage Locations',
      category: 'artists',
      content: 'Artworks can be assigned to physical storage locations: FlatFile (horizontal flat storage for works on paper), WallSpace (wall-mounted display areas), or Rack (vertical storage racks for canvases). This helps track where physical pieces are stored.'
    },
    // Troubleshooting
    {
      title: 'Resetting Your Password',
      category: 'troubleshooting',
      content: 'If you forget your password, click "Forgot password?" on the login screen. Enter your email to request a reset code. An administrator will review the request and send you a code to set a new password.'
    },
    // Admin (admin-only)
    {
      title: 'Managing Users & Roles',
      category: 'admin',
      content: 'Access the Admin Console to view all registered users. You can change user roles (Guest, Artist, Admin), assign artists to user accounts, or deactivate accounts. Use the search and filter options to find specific users.'
    },
    {
      title: 'Editing Legal Pages',
      category: 'admin',
      content: 'The Privacy Policy and Terms of Service pages can be edited from the Admin Console under the "Legal" tab. Use the rich text editor to format content. Changes are saved to the database and appear immediately on the public pages.'
    },
    {
      title: 'Reviewing Uploads',
      category: 'admin',
      content: 'Monitor uploaded photos from the Admin Console. You can view all uploads, filter by date or user, and remove inappropriate content. Each upload is logged with the uploader\'s information and timestamp.'
    },
    {
      title: 'Understanding Audit Logs',
      category: 'admin',
      content: 'The audit log tracks important system events: user logins, role changes, content uploads, and administrative actions. Access logs from the Admin Console to monitor platform activity and investigate issues.'
    }
  ];

  const faqs = [
    {
      q: 'What file formats are supported for uploads?',
      a: 'We support JPEG, PNG, WebP, and AVIF image formats. Each file can be up to 10MB in size. For best quality, we recommend uploading high-resolution images in JPEG or PNG format.'
    },
    {
      q: 'How do I become an artist on the platform?',
      a: 'Artist accounts are granted by administrators. Contact an admin through the contact form below or reach out to the gallery administration to request artist access. You\'ll need to provide some information about your work.'
    },
    {
      q: 'Can I delete my account?',
      a: 'Yes, you can request account deletion by contacting support. Note that this will remove your account and any associated data. Artworks you\'ve uploaded may be retained or removed based on gallery policy.'
    },
    {
      q: 'How do I change my password?',
      a: 'Go to the Account page (click your avatar in the top right, then "Manage your Account"). From there, you can update your password in the security section.'
    },
    {
      q: 'Why can\'t I see certain artworks?',
      a: 'Some artworks may be set to private by the artist or may be restricted based on your account type. Guest users see only public gallery items, while artists can view their own private works.'
    },
    {
      q: 'How do I report inappropriate content?',
      a: 'If you encounter content that violates our terms of service, please use the contact form below to report it. Include the artwork title or Photo ID and a brief description of the issue.'
    },
    {
      q: 'Is my data secure?',
      a: 'Yes, we take security seriously. Passwords are encrypted, sessions are secured, and we strip EXIF metadata from uploaded images to protect your privacy. See our Privacy Policy for more details.'
    }
  ];

  const toggleFaq = (index) => {
    expandedFaq = expandedFaq === index ? null : index;
  };

  const handleContact = () => {
    const subject = encodeURIComponent('Help Request from ' + contactName);
    const body = encodeURIComponent(`From: ${contactName} (${contactEmail})\n\n${contactMessage}`);
    window.open(`mailto:support@canvasandclay.local?subject=${subject}&body=${body}`, '_blank');
    contactSuccess = true;
    // Reset form after short delay
    setTimeout(() => {
      contactName = '';
      contactEmail = '';
      contactMessage = '';
      contactSuccess = false;
    }, 3000);
  };

  // Filter articles based on search, category, and admin status
  $: filteredArticles = articles.filter(article => {
    // Hide admin articles from non-admins
    if (article.category === 'admin' && $auth.user?.role !== 'admin') {
      return false;
    }
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

    <!-- Quick Links -->
    <div class="quick-links">
      <a href="/gallery" class="quick-link">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
        Browse Gallery
      </a>
      {#if $auth.isAuthenticated && ($auth.user?.role === 'artist' || $auth.user?.role === 'admin')}
        <a href="/uploads" class="quick-link">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
          Upload Artwork
        </a>
      {/if}
      {#if $auth.isAuthenticated}
        <a href="/account" class="quick-link">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
          Account Settings
        </a>
      {/if}
    </div>
  </div>

  <div class="help-container">
    <!-- What's New -->
    <div class="whats-new-banner">
      <div class="banner-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"></path><path d="M2 17l10 5 10-5"></path><path d="M2 12l10 5 10-5"></path></svg>
      </div>
      <span class="banner-label">What's New</span>
      <div class="banner-items">
        <span class="banner-item">Admin-editable legal pages</span>
        <span class="banner-divider">•</span>
        <span class="banner-item">Universal help button</span>
        <span class="banner-divider">•</span>
        <span class="banner-item">Dark/Light mode toggle</span>
      </div>
    </div>

    <!-- Category Navigation -->
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
      {#if $auth.user?.role === 'admin'}
        <button
          class="cat-btn admin-btn"
          class:active={activeCategory === 'admin'}
          on:click={() => activeCategory = 'admin'}
        >
          Admin
        </button>
      {/if}
    </div>

    <!-- Articles Grid -->
    <div class="articles-grid">
      {#each filteredArticles as article}
        <div class="article-card">
          <h3>{article.title}</h3>
          <p>{article.content}</p>
          <div class="article-footer">
            <span class="category-tag" class:admin-tag={article.category === 'admin'}>
              {article.category === 'admin' ? 'Admin' : categories.find(c => c.id === article.category)?.name}
            </span>
          </div>
        </div>
      {:else}
        <div class="no-results">
          <p>No articles found matching "{searchQuery}"</p>
        </div>
      {/each}
    </div>

    <!-- FAQ Accordion -->
    <div class="faq-section">
      <h2>Frequently Asked Questions</h2>
      <div class="faq-list">
        {#each faqs as faq, i}
          <div class="faq-item" class:expanded={expandedFaq === i}>
            <button class="faq-question" on:click={() => toggleFaq(i)}>
              <span>{faq.q}</span>
              <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="6 9 12 15 18 9"></polyline>
              </svg>
            </button>
            {#if expandedFaq === i}
              <div class="faq-answer">
                <p>{faq.a}</p>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </div>

    <!-- Contact Form -->
    <div class="contact-section">
      <h2>Still need help?</h2>
      <p>Send us a message and we'll get back to you as soon as possible.</p>

      {#if contactSuccess}
        <div class="success-message">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          <span>Message sent! We'll be in touch soon.</span>
        </div>
      {:else}
        <form class="contact-form" on:submit|preventDefault={handleContact}>
          <div class="form-row">
            <input
              type="text"
              placeholder="Your name"
              bind:value={contactName}
              required
            />
            <input
              type="email"
              placeholder="Your email"
              bind:value={contactEmail}
              required
            />
          </div>
          <textarea
            placeholder="How can we help you?"
            bind:value={contactMessage}
            rows="4"
            required
          ></textarea>
          <button type="submit" class="submit-btn">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
            Send Message
          </button>
        </form>
      {/if}
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
    padding: 4rem 2rem 3rem;
    text-align: center;
    border-bottom: 1px solid var(--border-color);
  }

  .help-header h1 {
    font-size: 2rem;
    color: var(--text-primary);
    margin-bottom: 2rem;
    font-weight: 600;
  }

  /* What's New Banner */
  .whats-new-banner {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.875rem 1.25rem;
    background: linear-gradient(135deg, rgba(0, 122, 255, 0.1) 0%, rgba(99, 102, 241, 0.1) 100%);
    border: 1px solid rgba(0, 122, 255, 0.2);
    border-radius: 10px;
    margin-bottom: 2rem;
    flex-wrap: wrap;
  }

  .banner-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    background: var(--accent-color);
    border-radius: 8px;
    color: white;
    flex-shrink: 0;
  }

  .banner-label {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--accent-color);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .banner-items {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-left: auto;
  }

  .banner-item {
    font-size: 0.875rem;
    color: var(--text-primary);
  }

  .banner-divider {
    color: var(--text-secondary);
    opacity: 0.5;
  }

  .search-box {
    max-width: 600px;
    margin: 0 auto 2rem;
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

  /* Quick Links */
  .quick-links {
    display: flex;
    justify-content: center;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .quick-link {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1.25rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    color: var(--text-primary);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.9375rem;
    transition: all 0.15s ease;
  }

  .quick-link:hover {
    border-color: var(--accent-color);
    color: var(--accent-color);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
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

  .cat-btn.admin-btn {
    border-color: #f59e0b;
    color: #f59e0b;
  }

  .cat-btn.admin-btn:hover {
    background: rgba(245, 158, 11, 0.1);
  }

  .cat-btn.admin-btn.active {
    background: #f59e0b;
    color: white;
  }

  .articles-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
  }

  .article-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    transition: all 0.15s ease;
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
    font-weight: 600;
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

  .category-tag.admin-tag {
    color: #f59e0b;
  }

  .no-results {
    grid-column: 1 / -1;
    text-align: center;
    padding: 3rem;
    color: var(--text-secondary);
  }

  /* FAQ Section */
  .faq-section {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 2rem;
  }

  .faq-section h2 {
    margin: 0 0 1.5rem 0;
    color: var(--text-primary);
    font-size: 1.25rem;
    font-weight: 600;
  }

  .faq-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .faq-item {
    border: 1px solid var(--border-color);
    border-radius: 8px;
    overflow: hidden;
    transition: all 0.15s ease;
  }

  .faq-item.expanded {
    border-color: var(--accent-color);
  }

  .faq-question {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.25rem;
    background: var(--bg-primary);
    border: none;
    cursor: pointer;
    text-align: left;
    color: var(--text-primary);
    font-size: 0.9375rem;
    font-weight: 500;
    transition: all 0.15s ease;
  }

  .faq-question:hover {
    background: var(--bg-tertiary);
  }

  .faq-item.expanded .faq-question {
    background: var(--bg-tertiary);
  }

  .chevron {
    color: var(--text-secondary);
    transition: transform 0.2s ease;
    flex-shrink: 0;
  }

  .faq-item.expanded .chevron {
    transform: rotate(180deg);
    color: var(--accent-color);
  }

  .faq-answer {
    padding: 1rem 1.25rem;
    background: var(--bg-primary);
    border-top: 1px solid var(--border-color);
    animation: slideDown 0.2s ease-out;
  }

  @keyframes slideDown {
    from {
      opacity: 0;
      transform: translateY(-8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .faq-answer p {
    margin: 0;
    color: var(--text-secondary);
    font-size: 0.9375rem;
    line-height: 1.6;
  }

  /* Contact Section */
  .contact-section {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
  }

  .contact-section h2 {
    margin: 0 0 0.5rem 0;
    color: var(--text-primary);
    font-size: 1.25rem;
    font-weight: 600;
  }

  .contact-section > p {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
  }

  .contact-form {
    max-width: 600px;
    margin: 0 auto;
    text-align: left;
  }

  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .contact-form input,
  .contact-form textarea {
    width: 100%;
    padding: 0.875rem 1rem;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.9375rem;
    transition: all 0.15s ease;
    box-sizing: border-box;
  }

  .contact-form input:focus,
  .contact-form textarea:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
  }

  .contact-form textarea {
    resize: vertical;
    min-height: 100px;
    margin-bottom: 1rem;
  }

  .submit-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.875rem 1.5rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 0.9375rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .submit-btn:hover {
    background: var(--accent-hover);
    transform: translateY(-1px);
  }

  .success-message {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    padding: 1.5rem;
    background: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.3);
    border-radius: 8px;
    color: #22c55e;
    font-weight: 500;
  }

  @media (max-width: 768px) {
    .whats-new-banner {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.5rem;
    }

    .banner-items {
      margin-left: 0;
    }
  }

  @media (max-width: 600px) {
    .help-header {
      padding: 2rem 1rem 1.5rem;
    }

    .help-header h1 {
      font-size: 1.5rem;
    }

    .quick-links {
      flex-direction: column;
      align-items: stretch;
    }

    .help-container {
      padding: 1rem;
    }

    .articles-grid {
      grid-template-columns: 1fr;
    }

    .form-row {
      grid-template-columns: 1fr;
    }
  }
</style>
