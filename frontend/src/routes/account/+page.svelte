<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { auth } from '$lib/stores/auth';
  import { PUBLIC_API_BASE_URL } from '$env/static/public';

  let activeSection = 'profile';
  let loading = false;
  let error = '';
  let success = '';

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
        auth.update((state) => ({
          ...state,
          user: { ...state.user, email: data.user.email }
        }));
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
      <h2>Account</h2>
      <nav class="sidebar-nav">
        <button
          class="nav-item"
          class:active={activeSection === 'profile'}
          on:click={() => (activeSection = 'profile')}
        >
          Profile
        </button>
        <button
          class="nav-item"
          class:active={activeSection === 'password'}
          on:click={() => (activeSection = 'password')}
        >
          Password
        </button>
        <button
          class="nav-item"
          class:active={activeSection === 'email'}
          on:click={() => (activeSection = 'email')}
        >
          Email
        </button>
        {#if $auth.user?.role === 'admin'}
          <button
            class="nav-item admin-only"
            class:active={activeSection === 'admin'}
            on:click={() => (activeSection = 'admin')}
          >
            Admin
          </button>
        {/if}
      </nav>
    </aside>

    <main class="account-content">
      {#if activeSection === 'profile'}
        <div class="section">
          <h1>Profile</h1>
          <div class="profile-info">
            <div class="info-row">
              <label>Email</label>
              <span>{$auth.user?.email || '—'}</span>
            </div>
            <div class="info-row">
              <label>Role</label>
              <span class="role-badge">{$auth.user?.role || '—'}</span>
            </div>
            <div class="info-row">
              <label>Account Created</label>
              <span>
                {#if $auth.user?.created_at}
                  {new Date($auth.user.created_at).toLocaleDateString()}
                {:else}
                  —
                {/if}
              </span>
            </div>
          </div>
        </div>
      {:else if activeSection === 'password'}
        <div class="section">
          <h1>Change Password</h1>
          <p class="section-description">
            Update your password. You'll need to enter your current password to make changes.
          </p>

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
                {passwordLoading ? 'Updating...' : 'Update Password'}
              </button>
            </div>
          </form>
        </div>
      {:else if activeSection === 'email'}
        <div class="section">
          <h1>Change Email</h1>
          <p class="section-description">
            Update your email address. You'll need to enter your password to confirm this change.
          </p>

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
                {emailLoading ? 'Updating...' : 'Update Email'}
              </button>
            </div>
          </form>
        </div>
      {:else if activeSection === 'admin' && $auth.user?.role === 'admin'}
        <div class="section">
          <h1>Admin Information</h1>
          <p class="section-description">Your personal administrative account details and activity.</p>

          {#if adminInfoLoading}
            <div class="loading">Loading admin information...</div>
          {:else if adminInfo}
            <div class="admin-info-grid">
              <div class="info-section">
                <h2>Account Details</h2>
                <div class="info-card">
                  <div class="info-item">
                    <label>Account Created</label>
                    <span>{formatDate(adminInfo.account_info?.created_at)}</span>
                  </div>
                  <div class="info-item">
                    <label>Last Login</label>
                    <span>{formatDate(adminInfo.account_info?.last_login)}</span>
                  </div>
                  <div class="info-item">
                    <label>Password Last Changed</label>
                    <span>{formatDate(adminInfo.account_info?.password_last_changed)}</span>
                  </div>
                  <div class="info-item">
                    <label>Email Last Changed</label>
                    <span>{formatDate(adminInfo.account_info?.email_last_changed)}</span>
                  </div>
                </div>
              </div>

              <div class="info-section">
                <h2>Your Statistics</h2>
                <div class="stats-grid">
                  <div class="stat-card">
                    <div class="stat-label">Password Resets Approved</div>
                    <div class="stat-value">{adminInfo.statistics?.password_resets_approved || 0}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Password Resets Denied</div>
                    <div class="stat-value">{adminInfo.statistics?.password_resets_denied || 0}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Users Promoted</div>
                    <div class="stat-value">{adminInfo.statistics?.users_promoted || 0}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Users Demoted</div>
                    <div class="stat-value">{adminInfo.statistics?.users_demoted || 0}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Photos Uploaded</div>
                    <div class="stat-value">{adminInfo.statistics?.photos_uploaded || 0}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Artworks</div>
                    <div class="stat-value">{adminInfo.statistics?.artworks_count || 0}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Assigned Artists</div>
                    <div class="stat-value">{adminInfo.statistics?.assigned_artists || 0}</div>
                  </div>
                </div>
              </div>

              <div class="info-section">
                <h2>Recent Actions</h2>
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
                <h2>Quick Links</h2>
                <div class="quick-links">
                  <a href="/admin/console" class="quick-link">
                    <span>Admin Console</span>
                  </a>
                  <a href="/admin/console?tab=security" class="quick-link">
                    <span>Security & Audit Logs</span>
                  </a>
                  <a href="/admin/console?tab=requests" class="quick-link">
                    <span>Password Reset Requests</span>
                  </a>
                  <a href="/admin/console?tab=users" class="quick-link">
                    <span>User Management</span>
                  </a>
                </div>
              </div>
            </div>
          {/if}
        </div>
      {/if}
    </main>
  </div>
</div>

<style>
  .account-page {
    min-height: calc(100vh - 80px);
    padding: 2rem;
    background: var(--bg-primary);
  }

  .account-container {
    max-width: 1200px;
    margin: 0 auto;
    display: grid;
    grid-template-columns: 250px 1fr;
    gap: 2rem;
  }

  .account-sidebar {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.5rem;
    height: fit-content;
    position: sticky;
    top: 2rem;
  }

  .account-sidebar h2 {
    margin: 0 0 1.5rem 0;
    font-size: 1.25rem;
    color: var(--text-primary);
    font-weight: 600;
  }

  .sidebar-nav {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .nav-item {
    padding: 0.75rem 1rem;
    background: transparent;
    border: none;
    border-radius: 4px;
    color: var(--text-secondary);
    text-align: left;
    cursor: pointer;
    font-size: 0.9375rem;
    font-weight: 500;
    transition: all 0.2s;
  }

  .nav-item:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .nav-item.active {
    background: var(--accent-color);
    color: white;
  }

  .nav-item.admin-only {
    border-top: 1px solid var(--border-color);
    margin-top: 0.5rem;
    padding-top: 1rem;
  }

  .account-content {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 2rem;
  }

  .section h1 {
    margin: 0 0 0.5rem 0;
    font-size: 1.75rem;
    color: var(--text-primary);
    font-weight: 600;
  }

  .section-description {
    color: var(--text-secondary);
    font-size: 0.9375rem;
    margin-bottom: 2rem;
  }

  .profile-info {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .info-row {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .info-row label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .info-row span {
    font-size: 1rem;
    color: var(--text-primary);
  }

  .role-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    background: var(--accent-color);
    color: white;
    border-radius: 12px;
    font-size: 0.875rem;
    font-weight: 600;
    text-transform: capitalize;
    width: fit-content;
  }

  .account-form {
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
    font-weight: 500;
    color: var(--text-primary);
  }

  .form-group input {
    padding: 0.875rem 1rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 1rem;
    transition: all 0.2s;
  }

  .form-group input:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 2px rgba(66, 133, 244, 0.1);
  }

  .form-group input:disabled,
  .disabled-input {
    opacity: 0.6;
    cursor: not-allowed;
    background: var(--bg-tertiary);
  }

  .password-input-group {
    position: relative;
    display: flex;
    align-items: stretch;
  }

  .password-input-group input {
    flex: 1;
    padding-right: 3.5rem;
  }

  .password-toggle {
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    background: transparent;
    border: none;
    cursor: pointer;
    color: var(--text-secondary);
    font-size: 0.875rem;
    padding: 0 1rem;
    min-width: 60px;
    border-radius: 0 4px 4px 0;
    transition: all 0.2s;
  }

  .password-toggle:hover {
    color: var(--text-primary);
  }

  .password-hint {
    font-size: 0.75rem;
    color: var(--text-secondary);
    margin-top: 0.25rem;
  }

  .password-strength {
    margin-top: 0.75rem;
  }

  .strength-label {
    color: var(--text-secondary);
    font-size: 0.95rem;
    margin-bottom: 0.35rem;
  }

  .strength-bars {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 6px;
  }

  .strength-bars div {
    height: 6px;
    background: var(--bg-tertiary);
    border-radius: 3px;
    transition: all 0.2s;
  }

  .strength-bars div.active {
    background: var(--accent-color);
  }

  .password-requirements {
    margin-top: 0.65rem;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.5rem;
  }

  .requirement {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
  }

  .requirement .icon {
    font-weight: bold;
  }

  .requirement.met {
    color: var(--success-color, #34a853);
  }

  .requirement.missing {
    color: var(--text-secondary);
  }

  .requirement.optional {
    opacity: 0.7;
  }

  .pill {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: capitalize;
  }

  .pill-weak {
    background: rgba(234, 67, 53, 0.12);
    color: #c5221f;
  }

  .pill-okay {
    background: rgba(255, 152, 0, 0.12);
    color: #b45309;
  }

  .pill-good {
    background: rgba(52, 168, 83, 0.12);
    color: #137333;
  }

  .pill-strong {
    background: rgba(52, 168, 83, 0.2);
    color: #137333;
  }

  .message {
    padding: 0.75rem 1rem;
    border-radius: 4px;
    font-size: 0.875rem;
  }

  .message.success {
    background: rgba(52, 168, 83, 0.1);
    color: #137333;
    border: 1px solid rgba(52, 168, 83, 0.3);
  }

  .message.error {
    background: rgba(234, 67, 53, 0.1);
    color: #c5221f;
    border: 1px solid rgba(234, 67, 53, 0.3);
  }

  .form-actions {
    margin-top: 0.5rem;
  }

  .primary-button {
    padding: 0.875rem 1.5rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.2s;
  }

  .primary-button:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .primary-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .admin-info-grid {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  .info-section {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .info-section h2 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
  }

  .info-card {
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .info-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .info-item label {
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .info-item span {
    font-size: 0.9375rem;
    color: var(--text-primary);
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
  }

  .stat-card {
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .stat-label {
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: capitalize;
  }

  .stat-value {
    font-size: 1.75rem;
    font-weight: 600;
    color: var(--text-primary);
  }

  .actions-list {
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    max-height: 400px;
    overflow-y: auto;
  }

  .action-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border-radius: 4px;
  }

  .action-type {
    font-size: 0.9375rem;
    font-weight: 500;
    color: var(--text-primary);
  }

  .action-time {
    font-size: 0.8125rem;
    color: var(--text-secondary);
  }

  .no-actions {
    text-align: center;
    color: var(--text-secondary);
    font-style: italic;
    padding: 2rem;
  }

  .quick-links {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .quick-link {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 1rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    text-decoration: none;
    color: var(--text-primary);
    transition: all 0.2s;
  }

  .quick-link:hover {
    background: var(--bg-tertiary);
    border-color: var(--accent-color);
    color: var(--accent-color);
  }

  .link-icon {
    font-size: 1.25rem;
  }

  .loading {
    color: var(--text-secondary);
    font-style: italic;
  }

  @media (max-width: 768px) {
    .account-container {
      grid-template-columns: 1fr;
    }

    .account-sidebar {
      position: static;
    }

    .sidebar-nav {
      flex-direction: row;
      overflow-x: auto;
    }
  }
</style>

