<script>
  import { theme } from '$lib/stores/theme';
</script>

<div class="legal-page">
  <div class="legal-container">
    <h1>Privacy Policy</h1>
    <p class="last-updated">Last updated: December 7, 2025</p>

    <section>
      <h2>1. Introduction</h2>
      <p>
        Welcome to Canvas and Clay. We respect your privacy and are committed to protecting your personal data. 
        This privacy policy will inform you as to how we look after your personal data when you visit our website 
        and tell you about your privacy rights.
      </p>
    </section>

    <section>
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

    <section>
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

    <section>
      <h2>4. Data Security</h2>
      <p>
        We have put in place appropriate security measures to prevent your personal data from being accidentally lost, used, or accessed in an unauthorized way. 
        We limit access to your personal data to those employees, agents, contractors, and other third parties who have a business need to know.
      </p>
    </section>

    <section>
      <h2>5. Your Legal Rights</h2>
      <p>
        Under certain circumstances, you have rights under data protection laws in relation to your personal data, including the right to request access, 
        correction, erasure, restriction, transfer, to object to processing, to portability of data and (where the lawful ground of processing is consent) to withdraw consent.
      </p>
    </section>

    <section>
      <h2>6. Contact Us</h2>
      <p>
        If you have any questions about this privacy policy or our privacy practices, please contact us through the administrative channels on the platform.
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
