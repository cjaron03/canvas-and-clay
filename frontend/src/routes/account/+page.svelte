<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { auth } from '$lib/stores/auth';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  let activeSection = 'profile';

  // password change
  let currentPassword = '';
  let newPassword = '';
  let confirmPassword = '';
  let showCurrentPassword = false;
  let showNewPassword = false;
  let showConfirmPassword = false;
  let passwordLoading = false;
  let passwordError = '';
  let passwordSuccess = '';

  // password strength
  let passwordRequirements = [];
  let strengthLabel = 'Weak';
  let strengthLevel = 0;

  // email change
  let newEmail = '';
  let emailPassword = '';
  let showEmailPassword = false;
  let emailLoading = false;
  let emailError = '';
  let emailSuccess = '';

  // admin-only stats
  let adminInfo = null;
  let adminInfoLoading = false;

  onMount(async () => {
    if (!$auth.isAuthenticated) {
      goto('/login');
      return;
    }
  });

  // password strength calculation
  $: passwordRequirements = [
    {
      key: 'length',
      label: 'At least 8 characters',
      met: newPassword.length >= 8,
      required: true
    },
    {
      key: 'upper',
      label: 'One uppercase letter',
      met: /[A-Z]/.test(newPassword),
      required: true
    },
    {
      key: 'lower',
      label: 'One lowercase letter',
      met: /[a-z]/.test(newPassword),
      required: true
    },
    {
      key: 'digit',
      label: 'One number',
      met: /\d/.test(newPassword),
      required: true
    },
    {
      key: 'symbol',
      label: 'Add a symbol (recommended)',
      met: /[^A-Za-z0-9]/.test(newPassword),
      required: false
    }
  ];

  $: {
    const requiredMet = passwordRequirements.filter((r) => r.required && r.met).length;
    const optionalMet = passwordRequirements.filter((r) => !r.required && r.met).length;
    const lengthBonus = newPassword.length >= 12 ? 1 : 0;
    const score = requiredMet + optionalMet + lengthBonus;
    strengthLevel = Math.max(0, Math.min(4, score));

    if (score <= 1) strengthLabel = 'Weak';
    else if (score === 2) strengthLabel = 'Okay';
    else if (score === 3) strengthLabel = 'Good';
    else strengthLabel = 'Strong';
  }

  const buildAuthedHeaders = async () => {
    const headers = {
      'Content-Type': 'application/json',
      accept: 'application/json'
    };

    let csrfToken = $auth?.csrfToken;
    if (!csrfToken) {
      try {
        const csrfResponse = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
          credentials: 'include'
        });
        if (csrfResponse.ok) {
          const csrfData = await csrfResponse.json();
          csrfToken = csrfData.csrf_token;
        }
      } catch (err) {
        console.error('Failed to fetch CSRF token:', err);
      }
    }

    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }

    return headers;
  };

  const handlePasswordChange = async () => {
    passwordError = '';
    passwordSuccess = '';

    if (!currentPassword) {
      passwordError = 'Current password is required';
      return;
    }

    if (!newPassword) {
      passwordError = 'New password is required';
      return;
    }

    if (newPassword !== confirmPassword) {
      passwordError = 'Passwords do not match';
      return;
    }

    passwordLoading = true;

    try {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/change-password`, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Failed to change password');
      }

      passwordSuccess = data.message || 'Password updated successfully';
      currentPassword = '';
      newPassword = '';
      confirmPassword = '';
    } catch (err) {
      passwordError = err?.message || 'Failed to change password';
    } finally {
      passwordLoading = false;
    }
  };

  const handleEmailChange = async () => {
    emailError = '';
    emailSuccess = '';

    if (!newEmail) {
      emailError = 'New email is required';
      return;
    }

    if (!emailPassword) {
      emailError = 'Password is required to change email';
      return;
    }

    emailLoading = true;

    try {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/auth/change-email`, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          new_email: newEmail.trim().toLowerCase(),
          password: emailPassword
        })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Failed to change email');
      }

      emailSuccess = data.message || 'Email updated successfully';
      // update auth store with new email
      if (data.user) {
        auth.updateUser({ email: data.user.email });
      }
      newEmail = '';
      emailPassword = '';
    } catch (err) {
      emailError = err?.message || 'Failed to change email';
    } finally {
      emailLoading = false;
    }
  };

  const loadAdminInfo = async () => {
    if ($auth.user?.role !== 'admin') return;

    adminInfoLoading = true;
    try {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/account/admin-info`, {
        credentials: 'include',
        headers: { accept: 'application/json', ...headers }
      });

      if (response.ok) {
        adminInfo = await response.json();
      } else {
        console.error('Failed to load admin info:', response.status, response.statusText);
        const errorData = await response.json().catch(() => ({}));
        console.error('Error details:', errorData);
      }
    } catch (err) {
      console.error('Failed to load admin info:', err);
    } finally {
      adminInfoLoading = false;
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '—';
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  const formatEventType = (eventType) => {
    return eventType
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  $: if (activeSection === 'admin' && $auth.user?.role === 'admin' && !adminInfo && !adminInfoLoading) {
    loadAdminInfo();
  }
</script>

<div class="account-page">
  <div class="account-container">
    <aside class="account-sidebar">
      <nav class="sidebar-nav">
        <button
          class="nav-item"
          class:active={activeSection === 'profile'}
          on:click={() => (activeSection = 'profile')}
        >
          <div class="nav-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
          </div>
          <span class="nav-label">Home</span>
        </button>
        <button
          class="nav-item"
          class:active={activeSection === 'email'}
          on:click={() => (activeSection = 'email')}
        >
          <div class="nav-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
          </div>
          <span class="nav-label">Personal info</span>
        </button>
        <button
          class="nav-item"
          class:active={activeSection === 'password'}
          on:click={() => (activeSection = 'password')}
        >
          <div class="nav-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
          </div>
          <span class="nav-label">Security</span>
        </button>
        {#if $auth.user?.role === 'admin'}
          <button
            class="nav-item"
            class:active={activeSection === 'admin'}
            on:click={() => (activeSection = 'admin')}
          >
             <div class="nav-icon">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
             </div>
             <span class="nav-label">Data & privacy</span>
          </button>
        {/if}
      </nav>
    </aside>

    <main class="account-content">
      {#if activeSection === 'profile'}
        <div class="content-header">
           <h1>Home</h1>
           <p class="subtitle">Control your profile and account settings</p>
        </div>
        
        <div class="card">
          <div class="card-header">
            <h2>Profile info</h2>
            <div class="card-desc">Basic info about your account</div>
          </div>
          
          <div class="info-row">
            <div class="info-label">Email</div>
            <div class="info-value">{$auth.user?.email || '—'}</div>
          </div>
          <div class="info-row">
            <div class="info-label">Role</div>
            <div class="info-value">
              <span class="role-badge">{$auth.user?.role || '—'}</span>
            </div>
          </div>
          <div class="info-row">
            <div class="info-label">Account Created</div>
            <div class="info-value">
              {#if $auth.user?.created_at}
                {new Date($auth.user.created_at).toLocaleDateString()}
              {:else}
                —
              {/if}
            </div>
          </div>
        </div>
        
      {:else if activeSection === 'password'}
         <div class="content-header">
           <h1>Security</h1>
           <p class="subtitle">Settings and recommendations to help you keep your account secure</p>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Signing in to your account</h2>
            <div class="card-desc">Change your password</div>
          </div>

          <form on:submit|preventDefault={handlePasswordChange} class="account-form">
            <div class="form-group">
              <label for="current-password">Current Password</label>
              <div class="password-input-group">
                {#if showCurrentPassword}
                  <input
                    id="current-password"
                    type="text"
                    bind:value={currentPassword}
                    placeholder="Enter current password"
                    required
                    disabled={passwordLoading}
                    autocomplete="current-password"
                  />
                {:else}
                  <input
                    id="current-password"
                    type="password"
                    bind:value={currentPassword}
                    placeholder="Enter current password"
                    required
                    disabled={passwordLoading}
                    autocomplete="current-password"
                  />
                {/if}
                <button
                  type="button"
                  class="password-toggle"
                  on:click={() => (showCurrentPassword = !showCurrentPassword)}
                  aria-label={showCurrentPassword ? 'Hide password' : 'Show password'}
                >
                  {showCurrentPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>

            <div class="form-group">
              <label for="new-password">New Password</label>
              <div class="password-input-group">
                {#if showNewPassword}
                  <input
                    id="new-password"
                    type="text"
                    bind:value={newPassword}
                    placeholder="Enter new password"
                    required
                    disabled={passwordLoading}
                    autocomplete="new-password"
                  />
                {:else}
                  <input
                    id="new-password"
                    type="password"
                    bind:value={newPassword}
                    placeholder="Enter new password"
                    required
                    disabled={passwordLoading}
                    autocomplete="new-password"
                  />
                {/if}
                <button
                  type="button"
                  class="password-toggle"
                  on:click={() => (showNewPassword = !showNewPassword)}
                  aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                >
                  {showNewPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              {#if newPassword}
                <div class="password-hint">Use 8 or more characters with a mix of letters, numbers & symbols</div>
                <div class="password-strength">
                  <div class="strength-label">
                    Password strength: <span class={`pill pill-${strengthLabel.toLowerCase()}`}>{strengthLabel}</span>
                  </div>
                  <div class="strength-bars">
                    {#each [0, 1, 2, 3] as index}
                      <div class:active={index < strengthLevel}></div>
                    {/each}
                  </div>
                </div>
                <div class="password-requirements">
                  {#each passwordRequirements as req}
                    <div class={`requirement ${req.met ? 'met' : 'missing'} ${req.required ? '' : 'optional'}`}>
                      <span class="icon">{req.met ? '✓' : '✕'}</span>
                      <span>{req.label}{!req.required ? ' (optional)' : ''}</span>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>

            <div class="form-group">
              <label for="confirm-password">Confirm New Password</label>
              <div class="password-input-group">
                {#if showConfirmPassword}
                  <input
                    id="confirm-password"
                    type="text"
                    bind:value={confirmPassword}
                    placeholder="Confirm new password"
                    required
                    disabled={passwordLoading}
                    autocomplete="new-password"
                  />
                {:else}
                  <input
                    id="confirm-password"
                    type="password"
                    bind:value={confirmPassword}
                    placeholder="Confirm new password"
                    required
                    disabled={passwordLoading}
                    autocomplete="new-password"
                  />
                {/if}
                <button
                  type="button"
                  class="password-toggle"
                  on:click={() => (showConfirmPassword = !showConfirmPassword)}
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>

            {#if passwordError}
              <div class="message error">{passwordError}</div>
            {/if}
            {#if passwordSuccess}
              <div class="message success">{passwordSuccess}</div>
            {/if}

            <div class="form-actions">
              <button type="submit" class="primary-button" disabled={passwordLoading}>
                {passwordLoading ? 'Updating...' : 'Change Password'}
              </button>
            </div>
          </form>
        </div>
      {:else if activeSection === 'email'}
        <div class="content-header">
           <h1>Personal info</h1>
           <p class="subtitle">Info about you and your preferences</p>
        </div>

        <div class="card">
          <div class="card-header">
            <h2>Contact info</h2>
            <div class="card-desc">Update your email address</div>
          </div>

          <form on:submit|preventDefault={handleEmailChange} class="account-form">
            <div class="form-group">
              <label for="current-email">Current Email</label>
              <input
                id="current-email"
                type="email"
                value={$auth.user?.email || ''}
                disabled
                class="disabled-input"
              />
            </div>

            <div class="form-group">
              <label for="new-email">New Email</label>
              <input
                id="new-email"
                type="email"
                bind:value={newEmail}
                placeholder="Enter new email address"
                required
                disabled={emailLoading}
                autocomplete="email"
              />
            </div>

            <div class="form-group">
              <label for="email-password">Password</label>
              <div class="password-input-group">
                {#if showEmailPassword}
                  <input
                    id="email-password"
                    type="text"
                    bind:value={emailPassword}
                    placeholder="Enter your password to confirm"
                    required
                    disabled={emailLoading}
                    autocomplete="current-password"
                  />
                {:else}
                  <input
                    id="email-password"
                    type="password"
                    bind:value={emailPassword}
                    placeholder="Enter your password to confirm"
                    required
                    disabled={emailLoading}
                    autocomplete="current-password"
                  />
                {/if}
                <button
                  type="button"
                  class="password-toggle"
                  on:click={() => (showEmailPassword = !showEmailPassword)}
                  aria-label={showEmailPassword ? 'Hide password' : 'Show password'}
                >
                  {showEmailPassword ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>

            {#if emailError}
              <div class="message error">{emailError}</div>
            {/if}
            {#if emailSuccess}
              <div class="message success">{emailSuccess}</div>
            {/if}

            <div class="form-actions">
              <button type="submit" class="primary-button" disabled={emailLoading}>
                {emailLoading ? 'Updating...' : 'Save'}
              </button>
            </div>
          </form>
        </div>
      {:else if activeSection === 'admin' && $auth.user?.role === 'admin'}
        <div class="content-header">
           <h1>Data & privacy</h1>
           <p class="subtitle">Admin console and statistics</p>
        </div>

        <div class="card">
          <div class="card-header">
             <h2>Admin Dashboard</h2>
          </div>
          
          <div class="card-content-padded">
            {#if adminInfoLoading}
              <div class="loading">Loading admin information...</div>
            {:else if adminInfo}
              <div class="admin-info-grid">
                <div class="info-section">
                  <h3>Account Details</h3>
                  <div class="info-card-sub">
                    <div class="info-item">
                      <span class="info-label">Account Created</span>
                      <span>{formatDate(adminInfo.account_info?.created_at)}</span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">Last Login</span>
                      <span>{formatDate(adminInfo.account_info?.last_login)}</span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">Password Last Changed</span>
                      <span>{formatDate(adminInfo.account_info?.password_last_changed)}</span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">Email Last Changed</span>
                      <span>{formatDate(adminInfo.account_info?.email_last_changed)}</span>
                    </div>
                  </div>
                </div>

                <div class="info-section">
                  <h3>Your Statistics</h3>
                  <div class="stats-grid">
                    <div class="stat-card">
                      <div class="stat-label">Password Resets</div>
                      <div class="stat-value">{adminInfo.statistics?.password_resets_approved || 0}</div>
                    </div>
                    <div class="stat-card">
                      <div class="stat-label">Users Promoted</div>
                      <div class="stat-value">{adminInfo.statistics?.users_promoted || 0}</div>
                    </div>
                    <div class="stat-card">
                      <div class="stat-label">Artworks</div>
                      <div class="stat-value">{adminInfo.statistics?.artworks_count || 0}</div>
                    </div>
                  </div>
                </div>

                <div class="info-section">
                  <h3>Recent Actions</h3>
                  <div class="actions-list">
                    {#if adminInfo.recent_actions && adminInfo.recent_actions.length > 0}
                      {#each adminInfo.recent_actions as action}
                        <div class="action-item">
                          <div class="action-type">{formatEventType(action.event_type)}</div>
                          <div class="action-time">{formatDate(action.created_at)}</div>
                        </div>
                      {/each}
                    {:else}
                      <div class="no-actions">No recent actions</div>
                    {/if}
                  </div>
                </div>

                <div class="info-section">
                  <h3>Quick Links</h3>
                  <div class="quick-links">
                    <a href="/admin/console" class="quick-link">
                      <span>Admin Console</span>
                    </a>
                    <a href="/admin/console?tab=security" class="quick-link">
                      <span>Security & Audit Logs</span>
                    </a>
                  </div>
                </div>
              </div>
            {/if}
          </div>
        </div>
      {/if}
    </main>
  </div>
</div>

<style>
  .account-page {
    min-height: calc(100vh - 64px);
    background: var(--bg-primary);
    padding: 0;
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

  .account-container {
    max-width: 1000px;
    margin: 0 auto;
    display: grid;
    grid-template-columns: 280px 1fr;
    min-height: calc(100vh - 64px);
  }

  /* Sidebar */
  .account-sidebar {
    padding: 2rem 0;
  }

  .sidebar-nav {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-right: 16px;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 0 24px 0 32px;
    height: 48px;
    background: transparent;
    border: none;
    border-radius: 0 24px 24px 0;
    color: var(--text-secondary);
    text-align: left;
    cursor: pointer;
    font-size: 0.9375rem;
    font-weight: 500;
    transition: all 0.15s ease;
  }

  .nav-item:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .nav-item.active {
    background: rgba(0, 122, 255, 0.1);
    color: var(--accent-color);
  }

  :global([data-theme='dark']) .nav-item.active {
    background: rgba(0, 122, 255, 0.15);
  }

  .nav-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    color: inherit;
  }

  /* Main Content */
  .account-content {
    padding: 2rem 2rem 4rem;
  }

  .content-header {
    margin-bottom: 2rem;
    text-align: center;
  }

  .content-header h1 {
    font-size: 1.75rem;
    font-weight: 400;
    color: var(--text-primary);
    margin: 0 0 0.5rem;
    letter-spacing: -0.5px;
  }

  .content-header .subtitle {
    font-size: 0.95rem;
    color: var(--text-secondary);
  }

  /* Cards */
  .card {
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  :global([data-theme='dark']) .card {
    box-shadow: none;
    background: var(--bg-secondary);
  }

  .card-header {
    padding: 1.5rem;
    border-bottom: 1px solid var(--border-color);
  }

  .card-header h2 {
    font-size: 1.125rem;
    font-weight: 400;
    margin: 0 0 0.25rem;
    color: var(--text-primary);
  }
  
  .card-desc {
    color: var(--text-secondary);
    font-size: 0.875rem;
  }
  
  .card-content-padded {
    padding: 1.5rem;
  }

  /* Info Rows */
  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border-color);
  }
  
  .info-row:last-child {
    border-bottom: none;
  }

  .info-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex: 0 0 150px;
  }

  .info-value {
    flex: 1;
    font-size: 1rem;
    color: var(--text-primary);
    text-align: right;
  }

  .role-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    background: var(--accent-color);
    color: white;
    border-radius: 12px;
    font-size: 0.875rem;
    font-weight: 500;
    text-transform: capitalize;
  }

  /* Forms */
  .account-form {
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .form-group label {
    font-size: 0.875rem;
    color: var(--text-secondary);
    font-weight: 500;
  }

  .form-group input {
    padding: 12px 0;
    background: transparent;
    border: none;
    border-bottom: 1px solid var(--border-color);
    color: var(--text-primary);
    font-size: 1rem;
    transition: border-color 0.2s;
    border-radius: 0;
  }

  .form-group input:focus {
    outline: none;
    border-bottom-color: var(--accent-color);
    border-bottom-width: 2px;
    padding-bottom: 11px; /* Adjust for border width change */
  }

  .form-group input:disabled,
  .disabled-input {
    opacity: 0.6;
    cursor: not-allowed;
    color: var(--text-secondary);
  }

  .password-input-group {
    position: relative;
    display: flex;
    align-items: center;
  }

  .password-input-group input {
    flex: 1;
    padding-right: 3.5rem;
  }

  .password-toggle {
    position: absolute;
    right: 0;
    background: transparent;
    border: none;
    cursor: pointer;
    color: var(--accent-color);
    font-size: 0.875rem;
    font-weight: 500;
    padding: 8px;
  }

  /* Actions */
  .form-actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 1rem;
  }

  .primary-button {
    padding: 0 28px;
    height: 44px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 22px;
    font-size: 0.95rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 1px 2px rgba(0,0,0,0.1);
  }

  .primary-button:hover:not(:disabled) {
    filter: brightness(1.05);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
    transform: translateY(-1px);
  }

  .primary-button:active:not(:disabled) {
    transform: translateY(0);
  }

  .primary-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    box-shadow: none;
    transform: none;
    filter: none;
  }

  /* Messages */
  .message {
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 0.9rem;
  }

  .message.success {
    background: rgba(52, 168, 83, 0.1);
    color: #34a853;
  }

  .message.error {
    background: rgba(234, 67, 53, 0.08);
    color: #ea4335;
  }

  /* Admin Section */
  .admin-info-grid {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }
  
  .info-section h3 {
     font-size: 1rem;
     font-weight: 500;
     margin-bottom: 1rem;
     color: var(--text-primary);
  }
  
  .info-card-sub {
     background: var(--bg-tertiary);
     padding: 1rem;
     border-radius: 8px;
     display: grid;
     gap: 1rem;
  }
  
  .info-item {
    display: flex;
    justify-content: space-between;
    font-size: 0.875rem;
  }
  
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
  }
  
  .stat-card {
    background: var(--bg-tertiary);
    padding: 1rem;
    border-radius: 8px;
    text-align: center;
  }
  
  .stat-value {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--accent-color);
  }
  
  .actions-list {
     border: 1px solid var(--border-color);
     border-radius: 8px;
     max-height: 300px;
     overflow-y: auto;
  }
  
  .action-item {
     padding: 0.75rem 1rem;
     border-bottom: 1px solid var(--border-color);
     display: flex;
     justify-content: space-between;
  }
  
  .action-item:last-child {
     border-bottom: none;
  }
  
  .quick-links {
     display: flex;
     flex-wrap: wrap;
     gap: 0.5rem;
  }
  
  .quick-link {
     padding: 0.5rem 1rem;
     border: 1px solid var(--border-color);
     border-radius: 100px;
     text-decoration: none;
     color: var(--text-primary);
     font-size: 0.875rem;
     transition: all 0.2s;
  }
  
  .quick-link:hover {
     background: var(--bg-tertiary);
     color: var(--accent-color);
     border-color: var(--accent-color);
  }

  /* Password Strength */
  .password-hint {
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin-top: 0.5rem;
  }
  
  .password-strength {
    margin-top: 0.75rem;
  }
  
  .strength-bars {
    display: flex;
    gap: 4px;
    margin-top: 4px;
  }
  
  .strength-bars div {
    flex: 1;
    height: 4px;
    background: var(--bg-tertiary);
    border-radius: 2px;
  }
  
  .strength-bars div.active {
    background: var(--accent-color);
  }
  
  .password-requirements {
    margin-top: 0.75rem;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.5rem;
  }
  
  .requirement {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.75rem;
    color: var(--text-secondary);
  }
  
  .requirement.met {
    color: var(--success-color, #34a853);
  }

  @media (max-width: 768px) {
    .account-container {
      grid-template-columns: 1fr;
    }

    .account-sidebar {
      padding: 1rem 0;
      border-bottom: 1px solid var(--border-color);
    }

    .sidebar-nav {
      flex-direction: row;
      overflow-x: auto;
      padding: 0 1rem;
    }
    
    .nav-item {
       border-radius: 100px;
       padding: 0 16px;
       white-space: nowrap;
    }

    .account-content {
      padding: 1.5rem;
    }
  }
</style>