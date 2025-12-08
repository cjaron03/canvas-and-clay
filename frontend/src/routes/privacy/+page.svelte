<script>
  export let data;

  $: dynamicContent = data?.content;
  $: hasContent = dynamicContent && dynamicContent.content;

  const formatDate = (isoString) => {
    if (!isoString) return 'December 7, 2025';
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };
</script>

<div class="legal-page">
  <div class="legal-nav">
    <a href="/terms" class="nav-pill">
      Terms of Service
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
    </a>
  </div>

  <div class="legal-header">
    <div class="header-content">
      <h1>{hasContent ? dynamicContent.title : 'Privacy Policy'}</h1>
      <p class="last-updated">Last updated: {formatDate(hasContent ? dynamicContent.last_updated : null)}</p>
    </div>
  </div>

  <div class="legal-container">
    {#if hasContent}
      <div class="dynamic-content">
        {@html dynamicContent.content}
      </div>
    {:else}
      <section class="content-section">
        <h2>1. Introduction</h2>
        <p>
          Welcome to Canvas and Clay. We respect your privacy and are committed to protecting your personal data.
          This privacy policy will inform you as to how we look after your personal data when you visit our website
          and tell you about your privacy rights.
        </p>
      </section>

      <section class="content-section">
        <h2>2. The Data We Collect</h2>
        <p>
          We may collect, use, store and transfer different kinds of personal data about you which we have grouped together follows:
        </p>
        <ul>
          <li><strong>Identity Data:</strong> includes first name, last name, username or similar identifier.</li>
          <li><strong>Contact Data:</strong> includes email address.</li>
          <li><strong>Content Data:</strong> includes the photos, artwork images, and descriptions you upload to the platform.</li>
          <li><strong>Technical Data:</strong> includes internet protocol (IP) address, browser type and version, time zone setting and location, and operating system.</li>
        </ul>
      </section>

      <section class="content-section">
        <h2>3. How We Use Your Data</h2>
        <p>
          We will only use your personal data when the law allows us to. Most commonly, we will use your personal data in the following circumstances:
        </p>
        <ul>
          <li>To register you as a new customer or artist.</li>
          <li>To manage and display your artwork portfolio.</li>
          <li>To manage our relationship with you (including notifying you about changes to our terms or privacy policy).</li>
          <li>To administer and protect our business and this website.</li>
        </ul>
      </section>

      <section class="content-section">
        <h2>4. Data Security</h2>
        <p>
          We have put in place appropriate security measures to prevent your personal data from being accidentally lost, used, or accessed in an unauthorized way.
          We limit access to your personal data to those employees, agents, contractors, and other third parties who have a business need to know.
        </p>
      </section>

      <section class="content-section">
        <h2>5. Your Legal Rights</h2>
        <p>
          Under certain circumstances, you have rights under data protection laws in relation to your personal data, including the right to request access,
          correction, erasure, restriction, transfer, to object to processing, to portability of data and (where the lawful ground of processing is consent) to withdraw consent.
        </p>
      </section>

      <section class="content-section">
        <h2>6. Contact Us</h2>
        <p>
          If you have any questions about this privacy policy or our privacy practices, please contact us through the administrative channels on the platform.
        </p>
      </section>
    {/if}

  </div>
</div>

<style>
  .legal-page {
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

  .legal-nav {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    max-width: 800px;
    margin: 0 auto;
    padding: 1.5rem 2rem;
  }

  .nav-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--text-secondary);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.9375rem;
    padding: 0.625rem 1.25rem;
    border-radius: 24px;
    border: 1px solid var(--border-color);
    transition: all 0.15s ease;
    background: var(--bg-secondary);
  }

  .nav-pill:hover {
    color: var(--accent-color);
    border-color: var(--accent-color);
    transform: translateY(-2px);
    background: rgba(0, 122, 255, 0.04);
    box-shadow: 0 4px 12px rgba(0,0,0,0.06);
  }

  .legal-header {
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border-color);
    padding: 4rem 2rem;
    text-align: center;
  }

  .header-content {
    max-width: 800px;
    margin: 0 auto;
  }

  .legal-header h1 {
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0 0 0.75rem 0;
    background: linear-gradient(135deg, var(--accent-color) 0%, var(--accent-hover) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .last-updated {
    color: var(--text-secondary);
    font-size: 0.9375rem;
    margin: 0;
  }

  .legal-container {
    max-width: 800px;
    margin: 0 auto;
    padding: 3rem 2rem;
  }

  .content-section {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.02);
    transition: all 0.15s ease;
  }

  .content-section:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(0,0,0,0.06);
    border-color: var(--accent-color);
  }

  h2, .dynamic-content :global(h2) {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
    margin: 0 0 1rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .dynamic-content :global(h2) {
    margin-top: 2.5rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid var(--border-color);
  }

  .dynamic-content :global(h2:first-child) {
    margin-top: 0;
  }

  .dynamic-content :global(h1) {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-top: 2rem;
    margin-bottom: 1rem;
  }

  .dynamic-content :global(h3) {
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-top: 1.5rem;
    margin-bottom: 0.75rem;
  }

  p, .dynamic-content :global(p) {
    line-height: 1.7;
    color: var(--text-primary);
    margin: 0 0 1rem 0;
    font-size: 1rem;
  }

  ul, .dynamic-content :global(ul) {
    list-style-type: none;
    margin: 0 0 1rem 0;
    padding: 0;
    color: var(--text-primary);
  }

  .dynamic-content :global(ol) {
    list-style-type: none;
    margin: 0 0 1rem 0;
    padding: 0;
    color: var(--text-primary);
  }

  li, .dynamic-content :global(li) {
    margin-bottom: 0.75rem;
    line-height: 1.6;
    padding-left: 1.5rem;
    position: relative;
  }

  li::before, .dynamic-content :global(li)::before {
    content: '';
    position: absolute;
    left: 0;
    top: 0.6em;
    width: 6px;
    height: 6px;
    background: var(--accent-color);
    border-radius: 50%;
  }

  strong, .dynamic-content :global(strong) {
    color: var(--text-primary);
    font-weight: 600;
  }

  .dynamic-content :global(a) {
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 500;
    transition: opacity 0.15s ease;
  }

  .dynamic-content :global(a:hover) {
    opacity: 0.8;
  }

  /* Hide empty paragraphs and collapse extra whitespace */
  .dynamic-content :global(p:empty) {
    display: none;
  }

  .dynamic-content :global(p br:only-child) {
    display: none;
  }

  .dynamic-content :global(hr) {
    border: none;
    border-top: 1px solid var(--border-color);
    margin: 2.5rem 0;
  }

  @media (max-width: 768px) {
    .legal-nav {
      padding: 1rem;
    }

    .nav-pill {
      padding: 0.5rem 1rem;
      font-size: 0.875rem;
    }
    .legal-header {
      padding: 3rem 1.5rem;
    }

    .legal-header h1 {
      font-size: 2rem;
    }

    .legal-container {
      padding: 2rem 1rem;
    }

    .content-section {
      padding: 1.5rem;
    }
  }
</style>
