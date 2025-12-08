<script>
  import { theme } from '$lib/stores/theme';
</script>

<div class="legal-page">
  <div class="legal-container">
    <h1>Terms of Service</h1>
    <p class="last-updated">Last updated: December 7, 2025</p>

    <section>
      <h2>1. Agreement to Terms</h2>
      <p>
        These Terms of Service constitute a legally binding agreement made between you, whether personally or on behalf of an entity ("you") and 
        Canvas and Clay ("we," "us" or "our"), concerning your access to and use of the Canvas and Clay website as well as any other media form, 
        media channel, mobile website or mobile application related, linked, or otherwise connected thereto (collectively, the "Site").
      </p>
    </section>

    <section>
      <h2>2. Intellectual Property Rights</h2>
      <p>
        Unless otherwise indicated, the Site is our proprietary property and all source code, databases, functionality, software, website designs, 
        audio, video, text, photographs, and graphics on the Site (collectively, the "Content") and the trademarks, service marks, and logos contained 
        therein (the "Marks") are owned or controlled by us or licensed to us, and are protected by copyright and trademark laws.
      </p>
      <p>
        <strong>Artist Content:</strong> Artists retain full ownership and copyright of the artwork images they upload to the Site. By uploading content, 
        you grant Canvas and Clay a non-exclusive license to display, reproduce, and distribute your content solely for the purpose of operating and promoting the Site.
      </p>
    </section>

    <section>
      <h2>3. User Representations</h2>
      <p>
        By using the Site, you represent and warrant that:
      </p>
      <ul>
        <li>All registration information you submit will be true, accurate, current, and complete.</li>
        <li>You have the legal capacity and you agree to comply with these Terms of Service.</li>
        <li>You are not a minor in the jurisdiction in which you reside.</li>
        <li>You will not access the Site through automated or non-human means, whether through a bot, script or otherwise.</li>
        <li>Your use of the Site will not violate any applicable law or regulation.</li>
      </ul>
    </section>

    <section>
      <h2>4. Prohibited Activities</h2>
      <p>
        You may not access or use the Site for any purpose other than that for which we make the Site available. The Site may not be used in connection 
        with any commercial endeavors except those that are specifically endorsed or approved by us. As a user of the Site, you agree not to:
      </p>
      <ul>
        <li>Systematically retrieve data or other content from the Site to create or compile, directly or indirectly, a collection, compilation, database, or directory without written permission from us.</li>
        <li>Upload or transmit (or attempt to upload or to transmit) viruses, Trojan horses, or other material that interferes with any party's uninterrupted use and enjoyment of the Site.</li>
        <li>Delete the copyright or other proprietary rights notice from any Content.</li>
        <li>Harass, annoy, intimidate, or threaten any of our employees or agents engaged in providing any portion of the Site to you.</li>
        <li>Upload content that is illegal, infringing, defamatory, or otherwise objectionable.</li>
      </ul>
    </section>

    <section>
      <h2>5. Termination</h2>
      <p>
        We may terminate or suspend your account and bar access to the Service immediately, without prior notice or liability, under our sole discretion, 
        for any reason whatsoever and without limitation, including but not limited to a breach of the Terms.
      </p>
    </section>

    <section>
      <h2>6. Contact Us</h2>
      <p>
        In order to resolve a complaint regarding the Site or to receive further information regarding use of the Site, please contact us via the administration portal.
      </p>
    </section>
  </div>
</div>

<style>
  .legal-page {
    min-height: calc(100vh - 64px);
    background: var(--bg-primary);
    padding: 3rem 1.5rem;
  }

  .legal-container {
    max-width: 800px;
    margin: 0 auto;
    background: var(--bg-secondary);
    padding: 3rem;
    border-radius: 8px;
    border: 1px solid var(--border-color);
  }

  h1 {
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
  }

  .last-updated {
    color: var(--text-secondary);
    font-style: italic;
    margin-bottom: 3rem;
    font-size: 0.9375rem;
  }

  section {
    margin-bottom: 2.5rem;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 1rem;
  }

  p {
    line-height: 1.7;
    color: var(--text-primary);
    margin-bottom: 1rem;
    font-size: 1rem;
  }

  ul {
    list-style-type: disc;
    margin-left: 1.5rem;
    margin-bottom: 1rem;
    color: var(--text-primary);
  }

  li {
    margin-bottom: 0.5rem;
    line-height: 1.6;
  }

  strong {
    color: var(--text-primary);
    font-weight: 600;
  }

  @media (max-width: 768px) {
    .legal-container {
      padding: 1.5rem;
    }

    h1 {
      font-size: 2rem;
    }
  }
</style>
