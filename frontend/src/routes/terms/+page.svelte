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
    <a href="/privacy" class="nav-pill">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
      Privacy Policy
    </a>
  </div>

  <div class="legal-header">
    <div class="header-content">
      <h1>{hasContent ? dynamicContent.title : 'Terms of Service'}</h1>
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
        <h2>1. Agreement to Terms</h2>
        <p>These Terms of Service ("Terms") constitute a legally binding agreement between you ("you") and Canvas and Clay ("Canvas and Clay," "we," "us," or "our") concerning your access to and use of the Canvas and Clay website and any related media form, media channel, mobile website, or mobile application (collectively, the "Site").</p>
        <p>By accessing or using the Site, you represent that you have read, understood, and agree to be bound by these Terms. If you do not agree, you must not use the Site.</p>
      </section>

      <section class="content-section">
        <h2>2. Changes to Terms</h2>
        <p>We may update or revise these Terms from time to time. The "Last updated" date above reflects the most recent version. Your continued use of the Site after any revisions constitutes your acceptance of the updated Terms. If you do not agree to the new Terms, you must stop using the Site.</p>
      </section>

      <section class="content-section">
        <h2>3. Intellectual Property Rights</h2>
        <h3>3.1 Site Content and Marks</h3>
        <p>Unless otherwise indicated, the Site, including all source code, databases, functionality, software, website designs, audio, video, text, photographs, and graphics ("Content"), and the trademarks, service marks, and logos contained therein ("Marks"), are owned or licensed by Canvas and Clay and are protected by applicable intellectual property laws.</p>
        <p>Except as expressly permitted, no portion of the Site, Content, or Marks may be copied, reproduced, distributed, republished, archived, sold, or otherwise exploited for any commercial purpose without our prior written permission.</p>
        <h3>3.2 Artist Content</h3>
        <p>Artists retain all ownership and copyright in artwork, images, descriptions, and any other materials they upload ("Artist Content").</p>
        <p>By uploading Artist Content to the Site, you grant Canvas and Clay a worldwide, non-exclusive, royalty-free, transferable, and sublicensable license to:</p>
        <ul>
          <li>host, store, display, reproduce, modify (for technical purposes such as resizing), distribute, and</li>
          <li>use the Artist Content as necessary to operate, maintain, improve, and promote the Site.</li>
        </ul>
        <p>You represent and warrant that you own or have the necessary rights to upload the Artist Content and to grant the above license.</p>
      </section>

      <section class="content-section">
        <h2>4. User Eligibility and Account Responsibilities</h2>
        <p>By using the Site, you represent and warrant that:</p>
        <ol>
          <li>You are at least 18 years old (or the age of majority in your jurisdiction).</li>
          <li>Any registration information you submit is truthful, current, and complete.</li>
          <li>You will maintain the confidentiality of your login credentials and are responsible for all activity under your account.</li>
          <li>You will comply with all applicable laws and these Terms.</li>
        </ol>
        <p>We reserve the right to refuse service, suspend accounts, or remove content at our sole discretion.</p>
      </section>

      <section class="content-section">
        <h2>5. Prohibited Activities</h2>
        <p>You may use the Site only for lawful purposes and in accordance with these Terms. You agree not to:</p>
        <ul>
          <li>systematically retrieve data or content to create or compile databases without our permission;</li>
          <li>access the Site using unauthorized automated means (bots, scrapers, scripts), except for search engine indexing or tools we explicitly permit;</li>
          <li>upload or transmit viruses, malware, or any harmful code;</li>
          <li>interfere with the Site's functionality, security features, or infrastructure;</li>
          <li>delete or alter any copyright or proprietary notices;</li>
          <li>harass, threaten, or abuse any user, artist, employee, or representative;</li>
          <li>upload content that is illegal, defamatory, infringing, hateful, obscene, or otherwise objectionable.</li>
        </ul>
        <p>We may remove any content or suspend any user account at our discretion if we believe a violation has occurred.</p>
      </section>

      <section class="content-section">
        <h2>6. Termination</h2>
        <p>We may suspend or terminate your access to all or part of the Site, or remove any Artist Content or user content, at any time and for any reason, including for violations of these Terms, without notice or liability.</p>
        <p>Upon termination:</p>
        <ul>
          <li>your right to use the Site ends immediately;</li>
          <li>we may retain certain data as required for legal, security, or operational reasons.</li>
        </ul>
      </section>

      <section class="content-section">
        <h2>7. Disclaimer of Warranties</h2>
        <p>The Site and all Content are provided "AS IS" and "AS AVAILABLE."</p>
        <p>To the fullest extent permitted by law, we disclaim all warranties, express or implied, including:</p>
        <ul>
          <li>merchantability;</li>
          <li>fitness for a particular purpose;</li>
          <li>non-infringement;</li>
          <li>accuracy, availability, or reliability of the Site;</li>
          <li>that the Site will be uninterrupted, secure, or error-free.</li>
        </ul>
        <p>Your use of the Site is solely at your own risk.</p>
      </section>

      <section class="content-section">
        <h2>8. Limitation of Liability</h2>
        <p>To the fullest extent permitted by law, Canvas and Clay and its officers, directors, employees, and agents shall not be liable for:</p>
        <ul>
          <li>any indirect, incidental, consequential, special, punitive, or exemplary damages;</li>
          <li>loss of profits, data, goodwill, or other intangible losses;</li>
          <li>any damages arising from your use or inability to use the Site.</li>
        </ul>
        <p>Our total liability for any claim shall not exceed: (a) the amount you paid to us (if any) in the last twelve months, or (b) $100, whichever is greater.</p>
        <p>Some jurisdictions do not allow certain limitations; in such cases, our liability is limited to the maximum extent permitted by law.</p>
      </section>

      <section class="content-section">
        <h2>9. Indemnification</h2>
        <p>You agree to defend, indemnify, and hold harmless Canvas and Clay and its officers, directors, employees, and agents from any claims, damages, liabilities, losses, and expenses (including attorneys' fees) arising out of:</p>
        <ul>
          <li>your use of the Site,</li>
          <li>your Artist Content,</li>
          <li>your violation of these Terms or applicable law.</li>
        </ul>
      </section>

      <section class="content-section">
        <h2>10. Governing Law and Dispute Resolution</h2>
        <p>These Terms are governed by the laws of the State of California, without regard to conflict of law principles.</p>
        <p>Any legal action or proceeding shall be brought exclusively in the state or federal courts located in California, and you consent to personal jurisdiction in those courts.</p>
      </section>

      <section class="content-section">
        <h2>11. Privacy</h2>
        <p>Your use of the Site is also governed by our <a href="/privacy">Privacy Policy</a>, which describes how we collect, use, disclose, and protect your information.</p>
        <p>By using the Site, you consent to our data practices as described in the Privacy Policy.</p>
      </section>

      <section class="content-section">
        <h2>12. Miscellaneous</h2>
        <ul>
          <li>If any provision of these Terms is held invalid, the remaining provisions will remain in full force.</li>
          <li>Our failure to enforce any right or provision does not constitute a waiver.</li>
          <li>You may not assign these Terms; we may assign them without restriction.</li>
          <li>These Terms constitute the entire agreement between you and Canvas and Clay regarding the Site.</li>
        </ul>
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
    justify-content: flex-start;
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

  h3, .dynamic-content :global(h3) {
    font-size: 1.0625rem;
    font-weight: 600;
    color: var(--text-secondary);
    margin: 1.5rem 0 0.75rem 0;
  }

  .dynamic-content :global(h1) {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-top: 2rem;
    margin-bottom: 1rem;
  }

  p, .dynamic-content :global(p) {
    line-height: 1.7;
    color: var(--text-primary);
    margin: 0 0 1rem 0;
    font-size: 1rem;
  }

  ul, ol, .dynamic-content :global(ul), .dynamic-content :global(ol) {
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

  /* Numbered list items get numbers instead of bullets */
  ol li, .dynamic-content :global(ol li) {
    counter-increment: list-counter;
  }

  ol, .dynamic-content :global(ol) {
    counter-reset: list-counter;
  }

  ol li::before, .dynamic-content :global(ol li)::before {
    content: counter(list-counter);
    width: auto;
    height: auto;
    background: none;
    color: var(--accent-color);
    font-weight: 600;
    font-size: 0.875rem;
    top: 0;
  }

  strong, .dynamic-content :global(strong) {
    color: var(--text-primary);
    font-weight: 600;
  }

  a, .dynamic-content :global(a) {
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 500;
    transition: opacity 0.15s ease;
  }

  a:hover, .dynamic-content :global(a:hover) {
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
