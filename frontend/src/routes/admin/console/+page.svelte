<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { onMount, onDestroy } from 'svelte';
  import { get } from 'svelte/store';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { auth } from '$lib/stores/auth';

  let stats = null;
  let health = null;
  let loadError = null;
  let isLoading = true;

  // Load data client-side with credentials
  // Note: Consolidated into single onMount below to avoid duplicate health checks

  let activeTab = 'overview';
  let loading = {
    auditLog: false,
    failedLogins: false,
    users: false,
    database: false
  };

  let auditLogs = [];
  let auditLogPagination = null;
  let auditLogPage = 1;
  let auditLogEventType = '';
  let alertLogs = [];
  const ALERT_REVIEW_KEY = 'admin_security_alerts_review_state';
  const LEGACY_ALERT_REVIEW_KEY = 'admin_security_alerts_reviewed_at';
  let alertReviewState = { reviewedAt: null, reviewedIds: [] };

  let failedLogins = [];
  let failedLoginsPagination = null;
  let failedLoginsPage = 1;

  let users = [];
  let userRoleCounts = null;
  let userActionLoading = {};
  let userActionError = '';
  let userActionNotice = '';
  let artists = [];
  let loadingArtists = false;
  let assignUserId = '';
  let assignArtistId = '';
  let databaseInfo = null;
  let cleanup = {
    auditDays: 90,
    failedDays: 30,
    auditLoading: false,
    failedLoading: false,
    auditMessage: '',
    failedMessage: ''
  };
  let purgeMessage = '';
  let alertActionsMessage = '';
  let purgeDays = 30;
  let passwordResetRequests = [];
  let passwordResetPagination = null;
  let passwordResetPage = 1;
  let passwordResetFilter = 'all';
  let passwordResetLoading = false;
  let passwordResetError = '';
  let passwordResetNotice = '';
  let passwordResetActionLoading = {};
  let passwordResetAdminNotes = {};
  let passwordResetCodes = {};

  // API health check state
  let apiTestResult = null;
  let apiTestLoading = false;
  let lastApiCheck = null;
  let apiCheckInterval = null;
  let alertPollInterval = null;
  let currentTime = new Date(); // For reactive time display
  let overallHealthStatus = 'unknown'; // Overall system health status
  let isTabVisible = true; // Track if browser tab is visible

  // Backup state
  let backups = [];
  let backupsLoaded = false;
  let backupLoading = false;
  let backupError = '';
  let backupNotice = '';
  let backupInProgress = false;
  let backupProgress = null;
  let backupCurrentStep = '';
  let currentBackupId = null;
  let backupIncludeThumbnails = false;
  let backupExcludeAuditLogs = false;
  let backupDbOnly = false;
  let backupPhotosOnly = false;
  // Encryption options
  let backupEncrypt = false;
  let backupUseEnvKey = false;
  let backupPassphrase = '';
  let backupPassphraseConfirm = '';
  let encryptionConfigLoaded = false;
  let envKeyConfigured = false;
  // Restore encryption
  let restorePassphrase = '';
  let restoreUseEnvKey = false;
  let restoreInProgress = false;
  let restoreProgress = null;
  let restoreCurrentStep = '';
  let currentRestoreId = null;
  let selectedBackupForRestore = null;
  let restoreValidation = null;
  let restoreConfirmationPending = false;
  let restoreDbOnly = false;
  let restorePhotosOnly = false;
  let restoreSkipPreBackup = false;

  // Legal pages state
  let legalLoading = false;
  let legalError = '';
  let legalNotice = '';
  let legalSaving = false;
  let legalLoaded = false;
  let legalActivePage = 'privacy_policy';
  let legalPages = {
    privacy_policy: { title: 'Privacy Policy', content: '', last_updated: null, editor_email: null },
    terms_of_service: { title: 'Terms Of Service', content: '', last_updated: null, editor_email: null }
  };
  let quillEditor = null;
  let quillLoaded = false;

  // CLI state
  let writeMode = false;
  let commandInput = '';
  let commandHistory = [];
  let historyIndex = -1;
  let cliOutput = [];
  let cliHelp = null;
  let pendingDeleteConfirmation = null;
  let confirmationStep = 0; // 0 = none, 1 = first, 2 = second
  let cliOutputElement;
  let commandInputElement;
  let shouldAutoScroll = true; // track if we should auto-scroll (user at bottom)

  // check if user is at bottom of scroll (within 50px threshold)
  const isAtBottom = () => {
    if (!cliOutputElement) return false;
    const threshold = 50;
    const scrollTop = cliOutputElement.scrollTop;
    const scrollHeight = cliOutputElement.scrollHeight;
    const clientHeight = cliOutputElement.clientHeight;
    return scrollHeight - scrollTop - clientHeight < threshold;
  };

  // handle scroll events to track if user manually scrolled up
  const handleCLIScroll = () => {
    shouldAutoScroll = isAtBottom();
  };

  // Save CLI output to localStorage for persistence
  const saveCLIOutput = () => {
    // Keep last 1000 lines (same limit as in-memory)
    const toSave = cliOutput.slice(-1000);
    try {
      localStorage.setItem('admin_cli_output', JSON.stringify(toSave));
    } catch (err) {
      // If localStorage is full, try saving less
      console.warn('Failed to save CLI output, localStorage may be full:', err);
      try {
        localStorage.setItem('admin_cli_output', JSON.stringify(toSave.slice(-500)));
      } catch {
        // If still fails, clear old output and try again
        console.warn('Clearing old CLI output due to storage limit');
        localStorage.removeItem('admin_cli_output');
      }
    }
  };

  // Load command history from localStorage and initialize console
  onMount(async () => {
    // Initialize auth first (layout also calls this, but we need to ensure it's done)
    await auth.init();
    
    // Read tab from URL query parameter
    const tabParam = $page.url.searchParams.get('tab');
    if (tabParam && ['overview', 'security', 'requests', 'users', 'database', 'cli', 'backup', 'legal'].includes(tabParam)) {
      activeTab = tabParam;
    }

    // Restore persisted alert review state so previously reviewed alerts stay hidden
    alertReviewState = readStoredAlertReviewState();
    
    // Wait for auth state to be ready and reactive updates to propagate
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Check auth state - redirect if not authenticated or not admin
    // Only redirect if we're still on the console page
    if (!$auth.isAuthenticated) {
      if ($page.url.pathname.startsWith('/admin/console')) {
        loadError = 'Authentication required. Please log in.';
        isLoading = false;
        goto('/login');
      }
      return;
    }
    
    if ($auth.user?.role !== 'admin') {
      if ($page.url.pathname.startsWith('/admin/console')) {
        loadError = 'Access denied: Admin role required';
        isLoading = false;
        goto('/');
      }
      return;
    }
    
    console.log('[ADMIN CONSOLE] Auth checks passed, loading data...');

    // Load stats and health data (only once on mount)
    // Only proceed if we're authenticated and admin
    try {
      // Build headers with CSRF token
      const headers = {
        accept: 'application/json'
      };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }
      
      const [statsRes, healthRes] = await Promise.all([
        fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/stats`, {
          credentials: 'include',
          headers: headers
        }),
        fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/health`, {
          credentials: 'include',
          headers: headers
        })
      ]);

      // Handle 401 - session might have expired
      // Only redirect if we're still on the console page
      if (statsRes.status === 401 || healthRes.status === 401) {
        if ($page.url.pathname.startsWith('/admin/console')) {
          loadError = 'Session expired. Please log in again.';
          isLoading = false;
          // Clear auth state and redirect to login
          auth.clear();
          goto('/login');
        }
        return;
      }

      if (statsRes.status === 403 || healthRes.status === 403) {
        if ($page.url.pathname.startsWith('/admin/console')) {
          loadError = 'Access denied: Admin role required';
          isLoading = false;
          goto('/');
        }
        return;
      }

      if (statsRes.ok) {
        stats = await statsRes.json();
        console.log('[ADMIN CONSOLE] Stats loaded:', stats);
      } else if (statsRes.status !== 429) {
        // Don't show error for rate limit (429) - it's expected
        loadError = `Failed to load stats: HTTP ${statsRes.status}`;
      }

      // Track if we successfully loaded health data
      let healthLoadedSuccessfully = false;
      
      if (healthRes.ok) {
        health = await healthRes.json();
        healthLoadedSuccessfully = true;
        console.log('[ADMIN CONSOLE] Health loaded:', health);
      } else if (healthRes.status === 429) {
        // Rate limited - preserve existing health status, don't overwrite with unknown
        // Only set to unknown if we have no health data at all
        if (!health) {
          health = { status: 'unknown', service: 'canvas-clay-backend' };
        }
        // Don't update overallHealthStatus if rate limited - keep existing value
      } else {
        // Actual error (not rate limit)
        if (!loadError) {
          loadError = `Failed to load health: HTTP ${healthRes.status}`;
        }
        // Only set to unknown on actual errors (not rate limits) if we have no data
        if (!health) {
          health = { status: 'unknown', service: 'canvas-clay-backend' };
        }
      }

      // Only set default if we truly have no health data
      if (!health) {
        health = { status: 'unknown', service: 'canvas-clay-backend' };
      }

      // Initialize overall health status from backend health
      // Only update if we successfully loaded health (not rate limited or error)
      if (healthLoadedSuccessfully) {
        overallHealthStatus = health?.status || 'unknown';
      } else if (!overallHealthStatus || overallHealthStatus === 'unknown') {
        // Only set to unknown if we don't have a previous status and couldn't load
        overallHealthStatus = health?.status || 'unknown';
      }
      // If rate limited/error and we have a previous status, preserve it

      // Start periodic API check (but don't call refreshHealthData immediately - we already have health data)
      // Only start the interval, don't run initial checks
      if (apiCheckInterval) {
        clearInterval(apiCheckInterval);
      }
      // Set up periodic checks every 60 seconds, but skip the initial call since we already loaded health
      // Only check health endpoint, not root endpoint (to avoid rate limits)
      apiCheckInterval = setInterval(() => {
        if (!isRateLimited) {
          refreshHealthData();
          // Only test root endpoint every 5 minutes to avoid rate limits
          // testApiConnection is called manually via button click
        }
      }, 60000);

      // Load CLI help
      await loadCLIHelp();

      // Preload users to align role-based artist count in overview
      await loadUsers();
      syncArtistCountFromRoles();

      // Preload users to sync role-based artist count in overview
      await loadUsers();

      // Load command history
      const storedHistory = localStorage.getItem('admin_cli_history');
      if (storedHistory) {
        try {
          commandHistory = JSON.parse(storedHistory);
        } catch {
          commandHistory = [];
        }
      }

      // Set up page visibility listener to pause/resume API checks
      if (typeof document !== 'undefined') {
        isTabVisible = document.visibilityState === 'visible';
        document.addEventListener('visibilitychange', handleVisibilityChange);
      }
    } catch (err) {
      console.error('Failed to load admin console data:', err);
      loadError = err instanceof Error ? err.message : 'Failed to load admin console data';
    } finally {
      isLoading = false;
    }
  });

  const loadCLIHelp = async () => {
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/cli/help`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });
      if (response.ok) {
        cliHelp = await response.json();
      }
    } catch (err) {
      console.error('Failed to load CLI help:', err);
    }
  };

  const saveCommandHistory = () => {
    // Keep last 50 commands
    const toSave = commandHistory.slice(-50);
    localStorage.setItem('admin_cli_history', JSON.stringify(toSave));
  };

  const addToHistory = (command) => {
    // Don't add duplicates
    if (commandHistory[commandHistory.length - 1] !== command) {
      commandHistory.push(command);
      saveCommandHistory();
    }
    historyIndex = commandHistory.length;
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    try {
      // Parse the date string - if it doesn't have timezone info, assume UTC
      let date;
      if (dateString.endsWith('Z') || dateString.includes('+') || dateString.includes('-', 10)) {
        // Has timezone info, parse directly
        date = new Date(dateString);
      } else {
        // No timezone info, assume UTC and append 'Z'
        date = new Date(dateString + (dateString.includes('T') ? 'Z' : ''));
      }
      
      // Check if date is valid
      if (isNaN(date.getTime())) {
        return dateString;
      }
      
      // Format in local timezone (automatically converts from UTC)
      return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
        timeZoneName: 'short'
      });
    } catch {
      return dateString;
    }
  };

  const loadAuditLogs = async (page = 1, eventType = '') => {
    loading.auditLog = true;
    try {
      const params = new URLSearchParams();
      params.set('page', page.toString());
      params.set('per_page', '50');
      if (eventType) params.set('event_type', eventType);

      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/audit-log?${params.toString()}`,
        {
          credentials: 'include',
          headers: { accept: 'application/json' }
        }
      );

      if (response.ok) {
        const result = await response.json();
        auditLogs = result.audit_logs || [];
        auditLogPagination = result.pagination || null;
        auditLogPage = page;
      }
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      loading.auditLog = false;
    }
  };

  const readStoredAlertReviewState = () => {
    try {
      const raw = localStorage.getItem(ALERT_REVIEW_KEY);
      if (raw) {
        // Prefer structured state, but fall back to legacy string if needed
        try {
          const parsed = JSON.parse(raw);
          return {
            reviewedAt: parsed?.reviewedAt || null,
            reviewedIds: Array.isArray(parsed?.reviewedIds) ? parsed.reviewedIds : []
          };
        } catch {
          // Legacy: stored as ISO string
          return { reviewedAt: raw, reviewedIds: [] };
        }
      }
      // Legacy key support
      const legacy = localStorage.getItem(LEGACY_ALERT_REVIEW_KEY);
      if (legacy) {
        return { reviewedAt: legacy, reviewedIds: [] };
      }
      return { reviewedAt: null, reviewedIds: [] };
    } catch (err) {
      console.warn('Unable to read alert review state from storage:', err);
      return { reviewedAt: null, reviewedIds: [] };
    }
  };

  const persistAlertReviewState = (state) => {
    try {
      localStorage.setItem(
        ALERT_REVIEW_KEY,
        JSON.stringify({
          reviewedAt: state?.reviewedAt || null,
          reviewedIds: Array.isArray(state?.reviewedIds) ? state.reviewedIds : []
        })
      );
    } catch (err) {
      console.warn('Unable to persist alert review state:', err);
    }
  };

  const parseTimestamp = (value) => {
    if (!value) return null;
    const hasTz = /[zZ]|[+-]\d{2}:?\d{2}$/.test(value);
    const normalized = value.replace(/\.(\d{3})\d+/, '.$1'); // trim microseconds to ms
    const candidate = hasTz ? normalized : `${normalized}Z`; // treat tz-less as UTC
    const parsed = Date.parse(candidate);
    return Number.isNaN(parsed) ? null : parsed;
  };

  const filterReviewedAlerts = (logs = []) => {
    const { reviewedAt, reviewedIds } = alertReviewState || {};
    const reviewedIdSet = new Set(reviewedIds || []);
    const lastReviewedTs = parseTimestamp(reviewedAt);
    const hasReviewedMarker = Boolean(reviewedAt);

    return logs.filter((log) => {
      if (reviewedIdSet.has(log?.id)) return false;
      if (!lastReviewedTs) {
        // If we have a review marker string but can't parse it, hide by default
        if (hasReviewedMarker) return false;
        return true;
      }

      const createdTs = parseTimestamp(log?.created_at);
      // Hide if timestamp is missing/unparseable and we have a review marker (conservative)
      if (!createdTs) return !hasReviewedMarker;
      return createdTs > lastReviewedTs;
    });
  };

  const loadAlertLogs = async () => {
    try {
      // Re-read persisted state in case another tab/window updated it
      alertReviewState = readStoredAlertReviewState();

      const params = new URLSearchParams();
      params.set('alerts', 'true');
      params.set('limit', '10');

      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/audit-log?${params.toString()}`,
        {
          credentials: 'include',
          headers: { accept: 'application/json' }
        }
      );

      if (response.ok) {
        const result = await response.json();
        alertLogs = filterReviewedAlerts(result.audit_logs || []);

        // If everything was already reviewed, keep the reviewed banner visible
        if (alertLogs.length === 0 && alertReviewState?.reviewedAt) {
          alertActionsMessage =
            'Alerts marked as reviewed. New alerts will appear automatically when triggered.';
        }
      }
    } catch (err) {
      console.error('Failed to load alert logs:', err);
    }
  };

  const clearAlerts = async () => {
    const now = new Date().toISOString();
    // Record both timestamp and the ids we cleared so items without timestamps also stay hidden
    const reviewedIds = [...new Set(alertLogs.map((log) => log?.id).filter(Boolean))];
    alertReviewState = { reviewedAt: now, reviewedIds };
    persistAlertReviewState(alertReviewState);
    alertLogs = [];
    alertActionsMessage =
      'Alerts marked as reviewed. New alerts will appear automatically when triggered.';
  };

  const loadFailedLogins = async (page = 1) => {
    loading.failedLogins = true;
    try {
      const params = new URLSearchParams();
      params.set('page', page.toString());
      params.set('per_page', '50');

      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/failed-logins?${params.toString()}`,
        {
          credentials: 'include',
          headers: { accept: 'application/json' }
        }
      );

      if (response.ok) {
        const result = await response.json();
        failedLogins = result.failed_logins || [];
        failedLoginsPagination = result.pagination || null;
        failedLoginsPage = page;
      }
    } catch (err) {
      console.error('Failed to load failed logins:', err);
    } finally {
      loading.failedLogins = false;
    }
  };

  const loadPasswordResetRequests = async (page = 1, status = passwordResetFilter) => {
    passwordResetLoading = true;
    passwordResetError = '';
    try {
      const headers = await buildAuthedHeaders();
      const params = new URLSearchParams({
        page: page.toString(),
        per_page: '10',
        status: status || 'all'
      });
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/password-resets?${params.toString()}`, {
        credentials: 'include',
        headers
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.error || 'Failed to load password reset requests');
      }
      passwordResetRequests = data.requests || [];
      passwordResetPagination = data.pagination || null;
      passwordResetPage = data.pagination?.page || page;
    } catch (err) {
      console.error('Failed to load password reset requests:', err);
      passwordResetError = err?.message || 'Failed to load password reset requests';
    } finally {
      passwordResetLoading = false;
    }
  };

  const handlePasswordResetAction = async (request, actionType, defaultError) => {
    if (!request?.id) return;
    const actionKey = `${request.id}-${actionType}`;
    passwordResetActionLoading = { ...passwordResetActionLoading, [actionKey]: true };
    passwordResetNotice = '';

    try {
      const headers = await buildAuthedHeaders();
      const endpoint = actionType === 'complete' ? 'mark-complete' : actionType;
      const note = (passwordResetAdminNotes[request.id] || '').trim();
      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/password-resets/${request.id}/${endpoint}`,
        {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify({ message: note })
        }
      );
      const data = await handleUserActionResponse(response, defaultError);
      if (actionType === 'approve' && data?.reset_code) {
        passwordResetCodes = { ...passwordResetCodes, [request.id]: data.reset_code };
      }
      passwordResetAdminNotes = { ...passwordResetAdminNotes, [request.id]: '' };
      passwordResetNotice = data?.message || 'Action completed successfully';
      await loadPasswordResetRequests(passwordResetPage, passwordResetFilter);
    } catch (err) {
      console.error(`Password reset action (${actionType}) failed:`, err);
      passwordResetError = err?.message || defaultError;
    } finally {
      passwordResetActionLoading = { ...passwordResetActionLoading, [actionKey]: false };
    }
  };

  const approvePasswordReset = (request) =>
    handlePasswordResetAction(request, 'approve', 'Failed to approve password reset request');

  const denyPasswordReset = (request) =>
    handlePasswordResetAction(request, 'deny', 'Failed to deny password reset request');

  const completePasswordReset = (request) =>
    handlePasswordResetAction(request, 'complete', 'Failed to update password reset request');

  const deletePasswordReset = async (request) => {
    if (!request?.id) return;
    const actionKey = `${request.id}-delete`;
    passwordResetActionLoading = { ...passwordResetActionLoading, [actionKey]: true };
    passwordResetNotice = '';
    passwordResetError = '';

    try {
      const headers = await buildAuthedHeaders();
      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/password-resets/${request.id}`,
        {
          method: 'DELETE',
          headers,
          credentials: 'include'
        }
      );
      const data = await handleUserActionResponse(response, 'Failed to delete password reset request');
      passwordResetNotice = data?.message || 'Password reset request deleted successfully';
      await loadPasswordResetRequests(passwordResetPage, passwordResetFilter);
    } catch (err) {
      console.error('Password reset delete failed:', err);
      passwordResetError = err?.message || 'Failed to delete password reset request';
    } finally {
      passwordResetActionLoading = { ...passwordResetActionLoading, [actionKey]: false };
    }
  };

  const isResetActionPending = (requestId) =>
    passwordResetActionLoading[`${requestId}-approve`] ||
    passwordResetActionLoading[`${requestId}-deny`] ||
    passwordResetActionLoading[`${requestId}-complete`] ||
    passwordResetActionLoading[`${requestId}-delete`];

  const recomputeRoleCounts = (list = users) => {
    const summary = {
      admin: 0,
      artist: 0,
      guest: 0,
      inactive: 0
    };

    (list || []).forEach((user) => {
      const roleKey = user.role === 'artist-guest' ? 'artist' : user.role;
      summary[roleKey] = (summary[roleKey] || 0) + 1;
      if (!user.is_active) {
        summary.inactive += 1;
      }
    });

    userRoleCounts = summary;
    syncArtistCountFromRoles();
  };

  const syncArtistCountFromRoles = () => {
    if (!stats || !stats.counts) return;
    const roleCount =
      (userRoleCounts?.artist || 0) + (userRoleCounts?.['artist-guest'] || 0) ||
      stats.counts.artist_users ||
      0;
    const maxArtists = Math.max(roleCount, stats.counts.artists || 0);
    stats = {
      ...stats,
      counts: { ...stats.counts, artists: maxArtists }
    };
  };

  const loadUsers = async () => {
    loading.users = true;
    userActionError = '';
    try {
      if (!users.length && !loadingArtists) {
        loadArtists();
      }
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });

      if (response.ok) {
        const result = await response.json();
        users = result.users || [];
        const counts = result.role_counts || null;
        if (counts) {
          userRoleCounts = {
            admin: counts.admin || 0,
            artist: (counts.artist || 0) + (counts['artist-guest'] || 0),
            guest: counts.guest || 0,
            inactive: counts.inactive || 0
          };
        } else {
          userRoleCounts = null;
        }
        if (!userRoleCounts) {
          recomputeRoleCounts(users);
        }
        syncArtistCountFromRoles();
      } else {
        userActionError = `Failed to load users (HTTP ${response.status})`;
      }
    } catch (err) {
      console.error('Failed to load users:', err);
      userActionError = err?.message || 'Failed to load users';
    } finally {
      loading.users = false;
    }
  };

  const loadArtists = async () => {
    loadingArtists = true;
    try {
      let response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/artists`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });

      // Fallback to public artists list if admin endpoint fails for any reason
      if (!response.ok) {
        response = await fetch(`${PUBLIC_API_BASE_URL}/api/artists_dropdown`, {
          headers: { accept: 'application/json' }
        });
      }

      if (response.ok) {
        const result = await response.json();
        artists = result.artists || [];
      } else {
        console.warn('Failed to load artists list (HTTP', response.status, ')');
      }
    } catch (err) {
      console.error('Failed to load artists:', err);
    } finally {
      loadingArtists = false;
    }
  };

  const loadDatabaseInfo = async () => {
    loading.database = true;
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/database-info`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });

      if (response.ok) {
        databaseInfo = await response.json();
      }
    } catch (err) {
      console.error('Failed to load database info:', err);
    } finally {
      loading.database = false;
    }
  };

  const ensureCsrfToken = async () => {
    let csrf = get(auth)?.csrfToken;
    if (csrf) return csrf;

    try {
      const resp = await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf-token`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });
      if (resp.ok) {
        const data = await resp.json();
        csrf = data.csrf_token;
        // Update store token without touching user state
        //auth.update({ csrfToken: csrf });
        auth.init(); // keep auth refreshed; token will be preserved now
      }
    } catch (err) {
      console.error('Failed to fetch CSRF token', err);
    }

    return csrf;
  };

  const buildAuthedHeaders = async () => {
    const headers = {
      'Content-Type': 'application/json',
      accept: 'application/json'
    };

    const csrfToken = await ensureCsrfToken();
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }

    return headers;
  };

  const updateUserInState = (updatedUser) => {
    if (!updatedUser) return;
    const idx = users.findIndex((u) => u.id === updatedUser.id);
    if (idx !== -1) {
      users = [...users.slice(0, idx), updatedUser, ...users.slice(idx + 1)];
    } else {
      users = [updatedUser, ...users];
    }
    recomputeRoleCounts(users);
  };

  const adjustArtistCount = (previousRole, newRole) => {
    if (!stats || !stats.counts) return;

    const wasArtist = previousRole === 'artist' || previousRole === 'artist-guest';
    const isArtist = newRole === 'artist' || newRole === 'artist-guest';

    if (isArtist && !wasArtist) {
      stats = {
        ...stats,
        counts: { ...stats.counts, artists: (stats.counts.artists || 0) + 1 }
      };
    } else if (!isArtist && wasArtist) {
      stats = {
        ...stats,
        counts: { ...stats.counts, artists: Math.max(0, (stats.counts.artists || 0) - 1) }
      };
    }
    // Keep role-count-derived value in sync
    syncArtistCountFromRoles();
  };

  const handleUserActionResponse = async (response, defaultError) => {
    const contentType = response.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await response.json() : null;

    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After');
      const retryMsg = retryAfter ? ` Please retry after ${retryAfter} seconds.` : '';
      throw new Error(data?.error || `Rate limit exceeded.${retryMsg}`);
    }

    if (!response.ok) {
      const debugSuffix = data?.debug
        ? ` [debug target_role=${data.debug.target_role}, normalized=${data.debug.target_normalized_role}, active=${data.debug.target_active}]`
        : '';
      throw new Error(
        (data?.error || defaultError || `Request failed (HTTP ${response.status})`) + debugSuffix
      );
    }

    if (data?.user) {
      updateUserInState(data.user);
    }

    return data;
  };

  const withUserAction = async (userId, action) => {
    userActionLoading = { ...userActionLoading, [userId]: true };
    userActionError = '';
    userActionNotice = '';
    try {
      await action();
    } catch (err) {
      console.error('User action failed:', err);
      userActionError = err?.message || 'Action failed. Please try again.';
    } finally {
      userActionLoading = { ...userActionLoading, [userId]: false };
    }
  };

  const promoteUser = async (user) =>
    withUserAction(user.id, async () => {
      const prevRole = user.role;
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users/${user.id}/promote`, {
        method: 'POST',
        credentials: 'include',
        headers
      });
      const result = await handleUserActionResponse(response, 'Failed to promote user');
      const newRole = result?.user?.role || prevRole;
      adjustArtistCount(prevRole, newRole);
    });

  const demoteUser = async (user) =>
    withUserAction(user.id, async () => {
      const prevRole = user.role;
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users/${user.id}/demote`, {
        method: 'POST',
        credentials: 'include',
        headers
      });
      const result = await handleUserActionResponse(response, 'Failed to demote user');
      const newRole = result?.user?.role || prevRole;
      adjustArtistCount(prevRole, newRole);
    });

  const toggleUserActive = async (user) =>
    withUserAction(user.id, async () => {
      const prevRole = user.role;
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users/${user.id}/toggle-active`, {
        method: 'POST',
        credentials: 'include',
        headers
      });
      const result = await handleUserActionResponse(
        response,
        user.is_active ? 'Failed to deactivate user' : 'Failed to reactivate user'
      );
      const newRole = result?.user?.role || prevRole;
      adjustArtistCount(prevRole, newRole);
    });

  const forceLogoutUser = async (user) =>
    withUserAction(user.id, async () => {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users/${user.id}/force-logout`, {
        method: 'POST',
        credentials: 'include',
        headers
      });
      await handleUserActionResponse(response, 'Failed to force logout user');
      userActionNotice = `Forced logout for ${user.email}. Active sessions will be revoked.`;
    });

  const assignArtistToUser = async () => {
    if (!assignUserId || !assignArtistId) {
      userActionError = 'Select both a user and an artist to assign.';
      return;
    }
    const headers = await buildAuthedHeaders();
    const response = await fetch(
      `${PUBLIC_API_BASE_URL}/api/admin/artists/${assignArtistId}/assign-user`,
      {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ user_id: assignUserId })
      }
    );
    const result = await handleUserActionResponse(response, 'Failed to assign artist');
    userActionNotice = result?.message || 'Artist assigned successfully';
    loadUsers();
    loadArtists();
  };

  const unassignArtist = async () => {
    if (!assignArtistId) {
      userActionError = 'Select an artist to unassign.';
      return;
    }
    const headers = await buildAuthedHeaders();
    const response = await fetch(
      `${PUBLIC_API_BASE_URL}/api/admin/artists/${assignArtistId}/unassign-user`,
      {
        method: 'POST',
        credentials: 'include',
        headers
      }
    );
    await handleUserActionResponse(response, 'Failed to unassign artist');
    userActionNotice = 'Artist unassigned successfully';
    loadUsers();
    loadArtists();
  };

  const softDeleteUser = async (user) =>
    withUserAction(user.id, async () => {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users/${user.id}/soft-delete`, {
        method: 'POST',
        credentials: 'include',
        headers
      });
      const result = await handleUserActionResponse(response, 'Failed to delete user');
      if (result?.user) {
        // Treat deleted user as inactive and keep role counts as-is
        recomputeRoleCounts(users);
      }
    });

  const restoreUser = async (user) =>
    withUserAction(user.id, async () => {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users/${user.id}/restore`, {
        method: 'POST',
        credentials: 'include',
        headers
      });
      const result = await handleUserActionResponse(response, 'Failed to restore user');
      if (result?.user) {
        recomputeRoleCounts(users);
      }
    });

  const purgeDeletedUsers = async () => {
    cleanup.auditMessage = '';
    cleanup.failedMessage = '';
    userActionError = '';
    purgeMessage = '';
    userActionLoading['__purge__'] = true;
    try {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users/purge-deleted`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ days: purgeDays })
      });
      const data = await handleUserActionResponse(response, 'Failed to purge deleted users');
      purgeMessage = data?.message || 'Purge complete';
      userActionNotice = purgeMessage;
      await loadUsers();
    } catch (err) {
      console.error('User purge failed:', err);
      userActionError = err?.message || 'Failed to purge deleted users';
    } finally {
      // Remove placeholder loading flag
      if (userActionLoading['__purge__']) {
        const copy = { ...userActionLoading };
        delete copy['__purge__'];
        userActionLoading = copy;
      }
    }
  };

  const hardDeleteUser = async (user) =>
    withUserAction(user.id, async () => {
      const headers = await buildAuthedHeaders();
      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/users/${user.id}/hard-delete`,
        {
          method: 'POST',
          credentials: 'include',
          headers
        }
      );
      const result = await handleUserActionResponse(response, 'Failed to delete user permanently');
      if (!response.ok) return;
      // Remove from local list
      users = users.filter((u) => u.id !== user.id);
      recomputeRoleCounts(users);
      userActionNotice = result?.message || 'User permanently deleted';
    });

  const cleanupAuditLogs = async () => {
    cleanup.auditMessage = '';
    cleanup.auditLoading = true;
    try {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/audit-log/cleanup`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ days: cleanup.auditDays })
      });
      const data = await handleUserActionResponse(response, 'Failed to cleanup audit logs');
      cleanup.auditMessage = data?.message || 'Cleanup complete';
      // Refresh audit logs
      loadAuditLogs(auditLogPage, auditLogEventType);
    } catch (err) {
      console.error('Audit log cleanup failed:', err);
      userActionError = err?.message || 'Failed to cleanup audit logs';
    } finally {
      cleanup.auditLoading = false;
    }
  };

  const cleanupFailedLogins = async () => {
    cleanup.failedMessage = '';
    cleanup.failedLoading = true;
    try {
      const headers = await buildAuthedHeaders();
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/failed-logins/cleanup`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ days: cleanup.failedDays })
      });
      const data = await handleUserActionResponse(response, 'Failed to cleanup failed logins');
      cleanup.failedMessage = data?.message || 'Cleanup complete';
      // Refresh failed login list
      loadFailedLogins(failedLoginsPage);
    } catch (err) {
      console.error('Failed login cleanup failed:', err);
      userActionError = err?.message || 'Failed to cleanup failed logins';
    } finally {
      cleanup.failedLoading = false;
    }
  };

  const handleTabChange = (tab) => {
    const previousTab = activeTab;
    activeTab = tab;
    
    // Stop API checks when leaving Overview tab, restart when returning
    if (previousTab === 'overview' && tab !== 'overview') {
      // Leaving Overview - stop API checks to free resources
      stopPeriodicApiCheck();
      // Stop time update interval
      if (timeUpdateInterval) {
        clearInterval(timeUpdateInterval);
        timeUpdateInterval = null;
      }
    } else if (previousTab !== 'overview' && tab === 'overview') {
      // Returning to Overview - restart API checks with immediate refresh
      startPeriodicApiCheck();
      // Restart time update interval if we have a lastApiCheck
      if (lastApiCheck && !timeUpdateInterval && isTabVisible) {
        timeUpdateInterval = setInterval(() => {
          if (document.visibilityState === 'visible' && activeTab === 'overview') {
            currentTime = new Date();
          }
        }, 1000);
      }
    }
    
    if (tab === 'security') {
      if (auditLogs.length === 0) {
        loadAuditLogs();
      }
      if (failedLogins.length === 0) {
        loadFailedLogins();
      }
      loadAlertLogs();
      startAlertPolling();
    } else {
      stopAlertPolling();
    }

    if (tab === 'requests' && passwordResetRequests.length === 0) {
      loadPasswordResetRequests();
    }

    if (tab === 'users' && users.length === 0) {
      loadUsers();
      loadArtists();
    } else if (tab === 'database' && !databaseInfo) {
      loadDatabaseInfo();
    } else if (tab === 'cli') {
      if (!cliHelp) {
        loadCLIHelp();
      }
      // Auto-focus input when CLI tab is activated
      setTimeout(() => {
        if (commandInputElement) {
          commandInputElement.focus();
        }
      }, 100);
    }
  };

  const testApiConnection = async () => {
    // Skip if we're rate limited
    if (isRateLimited) {
      return;
    }

    apiTestLoading = true;
    // Don't reset apiTestResult to null - keep previous result until new one is ready
    // This prevents the health badge from flickering back to healthy
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });
      
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const retryMsg = retryAfter ? ` Please wait ${retryAfter} seconds.` : '';
        const retrySeconds = retryAfter ? parseInt(retryAfter, 10) : 60;
        const checkTime = new Date();
        lastApiCheck = checkTime;
        currentTime = checkTime;
        
        // Set rate limit flag
        isRateLimited = true;
        rateLimitRetryAfter = retrySeconds;
        
        apiTestResult = {
          success: false,
          message: `Rate limit exceeded. Too many requests.${retryMsg}`
        };
        // Update overall health status directly
        overallHealthStatus = 'unhealthy';
        if (activeTab === 'cli') {
          addCLIOutput(`Rate limit warning: API health check rate limited.${retryMsg}`, 'warning');
        }
        
        // Auto-reset after retry period
        setTimeout(() => {
          isRateLimited = false;
          rateLimitRetryAfter = null;
        }, retrySeconds * 1000);
        
        apiTestLoading = false;
        return;
      }
      
      const data = await response.json();
      const checkTime = new Date();
      lastApiCheck = checkTime;
      // Update currentTime immediately to prevent negative time differences
      currentTime = checkTime;
      
      if (response.ok && data.message === 'Welcome to Canvas and Clay API') {
        apiTestResult = {
          success: true,
          message: data.message,
          status: data.status
        };
        // Force reactivity
        apiTestResult = { ...apiTestResult };
        // Update overall health status directly
        overallHealthStatus = health?.status || 'unknown';
        // Reset rate limit flag on success
        isRateLimited = false;
        rateLimitRetryAfter = null;
      } else {
        apiTestResult = {
          success: false,
          message: `Unexpected response: ${data.message || 'Unknown'}`
        };
        // Update overall health status directly
        overallHealthStatus = 'unhealthy';
      }
    } catch (err) {
      const checkTime = new Date();
      lastApiCheck = checkTime;
      // Update currentTime immediately to prevent negative time differences
      currentTime = checkTime;
      
      // Provide more helpful error messages
      let errorMessage = 'Connection failed';
      if (err.message === 'Failed to fetch') {
        errorMessage = 'Unable to connect to the API. The backend server may be down or unreachable. Check if the backend is running and accessible.';
      } else if (err.message.includes('NetworkError') || err.message.includes('network')) {
        errorMessage = 'Network error: Unable to reach the API server. Check your internet connection and ensure the backend is running.';
      } else if (err.message.includes('timeout')) {
        errorMessage = 'Request timed out: The API server took too long to respond. The server may be overloaded or experiencing issues.';
      } else {
        errorMessage = `Connection failed: ${err.message}. The API may be unavailable or experiencing issues.`;
      }
      
      // Create new object to ensure Svelte reactivity
      apiTestResult = {
        success: false,
        message: errorMessage
      };
      // Force reactivity by creating a new reference
      apiTestResult = { ...apiTestResult };
      // Update overall health status directly
      overallHealthStatus = 'unhealthy';
    } finally {
      apiTestLoading = false;
    }
  };

  let isRateLimited = false;
  let rateLimitRetryAfter = null;

  const refreshHealthData = async () => {
    // Skip if we're rate limited or not authenticated
    if (isRateLimited) {
      return;
    }

    // Don't make requests if not authenticated
    if (!$auth.isAuthenticated || $auth.user?.role !== 'admin') {
      // Stop the interval if we're not authenticated
      if (apiCheckInterval) {
        clearInterval(apiCheckInterval);
        apiCheckInterval = null;
      }
      return;
    }

    try {
      const healthRes = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/health`, {
        credentials: 'include',
        headers: {
          accept: 'application/json'
        }
      });
      
      if (healthRes.ok) {
        health = await healthRes.json();
        // Update overall health status if API test passed (don't override unhealthy from API test)
        if (apiTestResult && apiTestResult.success) {
          overallHealthStatus = health?.status || 'unknown';
        }
        // Reset rate limit flag on success
        isRateLimited = false;
        rateLimitRetryAfter = null;
      } else if (healthRes.status === 401) {
        // Session expired - stop interval and clear auth
        if (apiCheckInterval) {
          clearInterval(apiCheckInterval);
          apiCheckInterval = null;
        }
        auth.clear();
        goto('/login');
      } else if (healthRes.status === 429) {
        // Handle rate limiting
        isRateLimited = true;
        const retryAfter = healthRes.headers.get('Retry-After');
        rateLimitRetryAfter = retryAfter ? parseInt(retryAfter, 10) : 60;
        console.warn(`Rate limited on health check. Retry after ${rateLimitRetryAfter} seconds`);
        // Auto-reset after retry period
        setTimeout(() => {
          isRateLimited = false;
          rateLimitRetryAfter = null;
        }, rateLimitRetryAfter * 1000);
      }
    } catch (err) {
      console.error('Failed to refresh health data:', err);
      // Don't redirect on errors - just log
    }
  };

  const startPeriodicApiCheck = () => {
    // Clear existing interval if any
    if (apiCheckInterval) {
      clearInterval(apiCheckInterval);
      apiCheckInterval = null;
    }
    
    // Set up periodic checks every 60 seconds (reduced frequency to avoid rate limits)
    // Only check health endpoint, not root endpoint (to avoid rate limits)
    // testApiConnection is called manually via button click
    apiCheckInterval = setInterval(() => {
      if (!isRateLimited) {
        refreshHealthData();
      }
    }, 60000);
  };

  const stopPeriodicApiCheck = () => {
    if (apiCheckInterval) {
      clearInterval(apiCheckInterval);
      apiCheckInterval = null;
    }
  };

  const startAlertPolling = () => {
    stopAlertPolling();
    alertPollInterval = setInterval(() => {
      loadAlertLogs();
    }, 10000);
  };

  const stopAlertPolling = () => {
    if (alertPollInterval) {
      clearInterval(alertPollInterval);
      alertPollInterval = null;
    }
  };

  // Handle page visibility changes (pause/resume when browser tab is hidden/shown)
  const handleVisibilityChange = () => {
    const wasVisible = isTabVisible;
    isTabVisible = document.visibilityState === 'visible';
    
    // Only manage API checks if Overview tab is active
    if (activeTab !== 'overview') {
      return;
    }
    
    if (!wasVisible && isTabVisible) {
      // Browser tab became visible - restart periodic checks and time updates
      // Run immediate check to get fresh data
      startPeriodicApiCheck();
      // Restart time update interval if we have a lastApiCheck
      if (lastApiCheck && !timeUpdateInterval) {
        timeUpdateInterval = setInterval(() => {
          if (document.visibilityState === 'visible' && activeTab === 'overview') {
            currentTime = new Date();
          }
        }, 1000);
      }
    } else if (wasVisible && !isTabVisible) {
      // Browser tab became hidden - stop periodic checks and time updates to free resources
      stopPeriodicApiCheck();
      if (timeUpdateInterval) {
        clearInterval(timeUpdateInterval);
        timeUpdateInterval = null;
      }
    }
  };


  const formatTimeAgo = (date) => {
    if (!date) return 'Never';
    const now = currentTime; // Use reactive currentTime for live updates
    const diffMs = now - date;
    
    // Handle negative or very small differences (shouldn't happen, but prevent -1 seconds)
    if (diffMs < 0) {
      return 'just now';
    }
    
    const diffMins = Math.floor(diffMs / 60000);
    const diffSecs = Math.max(0, Math.floor((diffMs % 60000) / 1000)); // Ensure non-negative
    
    if (diffMins < 1) {
      if (diffSecs === 0) {
        return 'just now';
      }
      return `${diffSecs} second${diffSecs !== 1 ? 's' : ''} ago`;
    } else if (diffMins === 1) {
      return '1 minute ago';
    } else {
      return `${diffMins} minutes ago`;
    }
  };

  const handleCommandInput = (e) => {
    commandInput = e.target.value;
    // Autocomplete disabled
  };


  const executeCommand = async () => {
    if (!commandInput.trim()) return;

    const command = commandInput.trim();
    
    // Handle clear command locally
    if (command.toLowerCase() === 'clear' || command.toLowerCase() === 'cls') {
      addToHistory(command);
      commandInput = '';
      historyIndex = commandHistory.length;
      clearCLIOutput();
      setTimeout(() => {
        if (commandInputElement) {
          commandInputElement.focus();
        }
      }, 0);
      return;
    }
    
    addToHistory(command);
    commandInput = '';
    historyIndex = commandHistory.length;

    // when user executes a command, force scroll to show it
    shouldAutoScroll = true;

    // Add command to output
    addCLIOutput(`> ${command}`, 'command', true);

    // Auto-focus input after clearing (like a real CLI)
    setTimeout(() => {
      if (commandInputElement) {
        commandInputElement.focus();
      }
    }, 0);

    // Check for easter egg
    checkEasterEgg();

    try {
      // Ensure CSRF token is loaded
      const csrfToken = await ensureCsrfToken();

      const headers = {
        'Content-Type': 'application/json',
        accept: 'application/json'
      };

      if (csrfToken) {
        headers['X-CSRFToken'] = csrfToken;
      }
      
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/cli`, {
        method: 'POST',
        credentials: 'include',
        headers: headers,
        body: JSON.stringify({
          command: command,
          write_mode: writeMode,
          confirmation_token: pendingDeleteConfirmation?.token || null
        })
      });

      // Check for rate limiting
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const retryMsg = retryAfter ? ` Please wait ${retryAfter} seconds.` : '';
        addCLIOutput(`Rate limit exceeded: Too many requests.${retryMsg}`, 'error');
        addCLIOutput('Please wait before trying again.', 'warning');
        return;
      }

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        addCLIOutput(`Error: Server returned non-JSON response (HTTP ${response.status})`, 'error');
        if (response.status === 401) {
          addCLIOutput('Authentication required. Please log in again.', 'error');
        } else if (response.status === 403) {
          addCLIOutput('Access denied. Admin role required.', 'error');
        } else if (response.status === 404) {
          addCLIOutput('CLI endpoint not found. Please check API configuration.', 'error');
        } else {
          addCLIOutput(`Response: ${text.substring(0, 200)}...`, 'error');
        }
        return;
      }

      const result = await response.json();

      if (result.requires_confirmation && result.confirmation_token) {
        if (confirmationStep === 0) {
          // First confirmation for delete
          pendingDeleteConfirmation = {
            command: command,
            token: result.confirmation_token,
            data: result.data
          };
          confirmationStep = 1;
          addCLIOutput(`WARNING: This will delete a record.`, 'warning');
          addCLIOutput(`Type the command again to confirm deletion.`, 'warning');
        } else if (confirmationStep === 1 && pendingDeleteConfirmation && command === pendingDeleteConfirmation.command) {
          // Second confirmation - same command typed again
          confirmationStep = 2;
          addCLIOutput(`FINAL WARNING: Are you absolutely sure? This action cannot be undone.`, 'error');
          addCLIOutput(`Type the command one more time to proceed with deletion.`, 'error');
        } else {
          // Wrong command or state
          addCLIOutput(`Error: Please type the exact same command to confirm.`, 'error');
        }
      } else if (pendingDeleteConfirmation && confirmationStep === 2 && command === pendingDeleteConfirmation.command) {
        // Third confirmation - execute delete
        const deleteHeaders = {
          'Content-Type': 'application/json',
          accept: 'application/json'
        };
        
        // Add CSRF token if available
        if ($auth.csrfToken) {
          deleteHeaders['X-CSRFToken'] = $auth.csrfToken;
        }
        
        const deleteResponse = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/cli`, {
          method: 'POST',
          credentials: 'include',
          headers: deleteHeaders,
          body: JSON.stringify({
            command: command,
            write_mode: writeMode,
            confirmation_token: pendingDeleteConfirmation.token
          })
        });
        
        // Check for rate limiting on delete
        if (deleteResponse.status === 429) {
          const retryAfter = deleteResponse.headers.get('Retry-After');
          const retryMsg = retryAfter ? ` Please wait ${retryAfter} seconds.` : '';
          addCLIOutput(`Rate limit exceeded: Too many requests.${retryMsg}`, 'error');
          addCLIOutput('Please wait before trying again.', 'warning');
          pendingDeleteConfirmation = null;
          confirmationStep = 0;
          return;
        }
        
        // Check if response is JSON
        const deleteContentType = deleteResponse.headers.get('content-type');
        if (!deleteContentType || !deleteContentType.includes('application/json')) {
          const text = await deleteResponse.text();
          addCLIOutput(`Error: Server returned non-JSON response (HTTP ${deleteResponse.status})`, 'error');
          if (deleteResponse.status === 401) {
            addCLIOutput('Authentication required. Please log in again.', 'error');
          } else if (deleteResponse.status === 403) {
            addCLIOutput('Access denied. Admin role required.', 'error');
          } else {
            addCLIOutput(`Response: ${text.substring(0, 200)}...`, 'error');
          }
          pendingDeleteConfirmation = null;
          confirmationStep = 0;
          return;
        }
        
        const deleteResult = await deleteResponse.json();
        
        if (deleteResult.success) {
          addCLIOutput(deleteResult.output, 'success');
          if (deleteResult.data) {
            addCLIOutput(formatCLIData(deleteResult.data), 'data');
          }
        } else {
          addCLIOutput(deleteResult.output || deleteResult.error, 'error');
        }
        
        // Reset confirmation state
        pendingDeleteConfirmation = null;
        confirmationStep = 0;
      } else {
        // Command executed (non-delete or after confirmation)
        if (result.success) {
          addCLIOutput(result.output, 'success');
          if (result.data) {
            addCLIOutput(formatCLIData(result.data), 'data');
          }
        } else {
          addCLIOutput(result.output || result.error, 'error');
        }
        // Reset confirmation state if not a delete command
        if (!pendingDeleteConfirmation) {
          confirmationStep = 0;
        }
      }
      
      // Auto-scroll to bottom after command execution only if user is at bottom
      setTimeout(() => {
        if (cliOutputElement && shouldAutoScroll) {
          cliOutputElement.scrollTop = cliOutputElement.scrollHeight;
        }
        // Auto-focus input after command execution (like a real CLI)
        if (commandInputElement) {
          commandInputElement.focus();
        }
      }, 100);
    } catch (err) {
      addCLIOutput(`Error: ${err.message}`, 'error');
      pendingDeleteConfirmation = null;
      confirmationStep = 0;
      
      // Auto-focus input after error
      setTimeout(() => {
        if (commandInputElement) {
          commandInputElement.focus();
        }
      }, 0);
    }
  };

  const addCLIOutput = (text, type = 'info', forceScroll = false) => {
    cliOutput = [...cliOutput, {
      text,
      type,
      timestamp: new Date().toLocaleTimeString()
    }];
    // Keep last 1000 lines
    if (cliOutput.length > 1000) {
      cliOutput = cliOutput.slice(-1000);
    }
    // Save to localStorage for persistence
    saveCLIOutput();
    // Auto-scroll to bottom only if user is at bottom (or forced)
    if (forceScroll || shouldAutoScroll) {
      setTimeout(() => {
        if (cliOutputElement) {
          cliOutputElement.scrollTop = cliOutputElement.scrollHeight;
          // update shouldAutoScroll after scrolling
          shouldAutoScroll = isAtBottom();
        }
      }, 0);
    }
  };

  const formatCLIData = (data) => {
    if (Array.isArray(data)) {
      if (data.length === 0) return 'No results';
      // Format as table
      const keys = Object.keys(data[0]);
      let table = keys.join(' | ') + '\n';
      table += keys.map(() => '---').join(' | ') + '\n';
      for (const row of data.slice(0, 20)) {
        table += keys.map(k => String(row[k] || '')).join(' | ') + '\n';
      }
      if (data.length > 20) {
        table += `... and ${data.length - 20} more`;
      }
      return table;
    } else if (typeof data === 'object' && data !== null) {
      // Format help data nicely
      if (data.commands && Array.isArray(data.commands)) {
        let output = 'Available Commands:\n\n';
        for (const cmd of data.commands) {
          output += `  ${cmd.command}\n    ${cmd.description}\n\n`;
        }
        if (data.entities) {
          output += `Entities: ${data.entities.join(', ')}\n`;
        }
        if (data.actions) {
          output += `Actions: ${data.actions.join(', ')}\n`;
        }
        return output;
      }
      // Format other objects as JSON
      return JSON.stringify(data, null, 2);
    }
    return String(data);
  };

  const clearCLIOutput = () => {
    cliOutput = [];
    shouldAutoScroll = true; // reset to auto-scroll after clear
    // Clear from localStorage as well
    localStorage.removeItem('admin_cli_output');
  };

  const toggleWriteMode = (e) => {
    const newValue = e.target.checked;
    if (newValue && !writeMode) {
      // User is trying to enable write mode
      if (!confirm('WARNING: Enabling write mode allows you to modify the database. Are you sure?')) {
        // User cancelled - revert checkbox
        e.target.checked = false;
        writeMode = false;
        return;
      }
    }
    writeMode = newValue;
  };

  // Easter egg: randomly show "greetings, J here" message
  const checkEasterEgg = () => {
    // Check for test mode (via URL parameter or localStorage)
    const testEasterEgg = typeof window !== 'undefined' && (
      new URLSearchParams(window.location.search).get('test-easter-egg') === 'true' ||
      localStorage.getItem('test-easter-egg') === 'true'
    );
    
    // 1% chance to show easter egg (or 100% in test mode)
    const easterEggChance = testEasterEgg ? 1.0 : 0.01;
    if (Math.random() < easterEggChance) {
      const delay = testEasterEgg ? 100 : (500 + Math.random() * 2000); // Faster in test mode
      setTimeout(() => {
        addCLIOutput('greetings, J here', 'info');
        // McKenna was here 
      }, delay);
    }
  };

  const handleAuditLogFilter = () => {
    loadAuditLogs(1, auditLogEventType);
  };

  // Update currentTime every second for reactive display
  let timeUpdateInterval = null;
  
  // Reactive computed value for time ago display (depends on both lastApiCheck and currentTime)
  // Explicitly reference currentTime to ensure reactivity
  $: timeAgoDisplay = lastApiCheck && currentTime ? formatTimeAgo(lastApiCheck) : 'Never';
  
  // Update time display continuously when we have a lastApiCheck, tab is visible, and Overview tab is active
  $: if (lastApiCheck && isTabVisible && activeTab === 'overview') {
    // Clear existing interval
    if (timeUpdateInterval) {
      clearInterval(timeUpdateInterval);
    }
    // Start new interval to update time display
    timeUpdateInterval = setInterval(() => {
      // Only update if tab is still visible and Overview is active
      if (document.visibilityState === 'visible' && activeTab === 'overview') {
        currentTime = new Date();
      }
    }, 1000);
  } else {
    // Clear interval when no lastApiCheck, tab is hidden, or not on Overview tab
    if (timeUpdateInterval) {
      clearInterval(timeUpdateInterval);
      timeUpdateInterval = null;
    }
  }

  // ============================================================================
  // Backup & Restore Functions
  // ============================================================================

  const loadBackups = async () => {
    backupLoading = true;
    backupError = '';
    try {
      const headers = { accept: 'application/json' };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/backups`, {
        credentials: 'include',
        headers
      });
      if (response.ok) {
        const result = await response.json();
        backups = result.backups || [];
      } else {
        const err = await response.json();
        backupError = err.error || 'Failed to load backups';
      }
    } catch (err) {
      backupError = 'Failed to connect to server';
      console.error('Failed to load backups:', err);
    } finally {
      backupLoading = false;
      backupsLoaded = true;
    }
  };

  const loadEncryptionConfig = async () => {
    try {
      const headers = { accept: 'application/json' };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/backups/encryption-config`, {
        credentials: 'include',
        headers
      });
      if (response.ok) {
        const result = await response.json();
        envKeyConfigured = result.env_key_configured || false;
        encryptionConfigLoaded = true;
      }
    } catch (err) {
      console.error('Failed to load encryption config:', err);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const startBackup = async () => {
    // Validate encryption settings
    if (backupEncrypt && !backupUseEnvKey) {
      if (!backupPassphrase) {
        backupError = 'Please enter a passphrase for encryption';
        return;
      }
      if (backupPassphrase !== backupPassphraseConfirm) {
        backupError = 'Passphrases do not match';
        return;
      }
      if (backupPassphrase.length < 12) {
        backupError = 'Passphrase must be at least 12 characters';
        return;
      }
    }

    backupInProgress = true;
    backupError = '';
    backupNotice = '';
    backupCurrentStep = 'Starting backup...';
    backupProgress = 0;

    try {
      const headers = {
        'Content-Type': 'application/json',
        accept: 'application/json'
      };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }

      const requestBody = {
        db_only: backupDbOnly,
        photos_only: backupPhotosOnly,
        include_thumbnails: backupIncludeThumbnails,
        exclude_audit_logs: backupExcludeAuditLogs,
        encrypt: backupEncrypt
      };

      if (backupEncrypt) {
        if (backupUseEnvKey) {
          requestBody.use_env_key = true;
        } else {
          requestBody.passphrase = backupPassphrase;
        }
      }

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/backups/create`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        const result = await response.json();
        currentBackupId = result.backup_id;
        // Clear passphrase fields after successful start
        backupPassphrase = '';
        backupPassphraseConfirm = '';
        pollBackupStatus();
      } else {
        const err = await response.json();
        backupError = err.error || 'Failed to start backup';
        backupInProgress = false;
      }
    } catch (err) {
      backupError = 'Failed to connect to server';
      backupInProgress = false;
      console.error('Failed to start backup:', err);
    }
  };

  const pollBackupStatus = async () => {
    if (!currentBackupId) return;

    try {
      const headers = { accept: 'application/json' };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }

      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/backups/${currentBackupId}/status`,
        { credentials: 'include', headers }
      );

      if (response.ok) {
        const result = await response.json();
        backupProgress = result.progress || 0;
        backupCurrentStep = result.current_step || '';

        if (result.status === 'completed') {
          backupInProgress = false;
          backupNotice = 'Backup created successfully!';
          currentBackupId = null;
          loadBackups();
        } else if (result.status === 'failed') {
          backupInProgress = false;
          backupError = result.error || 'Backup failed';
          currentBackupId = null;
        } else {
          // Still in progress, poll again
          setTimeout(pollBackupStatus, 1000);
        }
      }
    } catch (err) {
      console.error('Failed to poll backup status:', err);
      setTimeout(pollBackupStatus, 2000);
    }
  };

  const deleteBackup = async (filename) => {
    if (!confirm(`Are you sure you want to delete backup "${filename}"?`)) {
      return;
    }

    try {
      const headers = { accept: 'application/json' };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }

      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/backups/${encodeURIComponent(filename)}`,
        {
          method: 'DELETE',
          credentials: 'include',
          headers
        }
      );

      if (response.ok) {
        backupNotice = 'Backup deleted successfully';
        loadBackups();
      } else {
        const err = await response.json();
        backupError = err.error || 'Failed to delete backup';
      }
    } catch (err) {
      backupError = 'Failed to connect to server';
      console.error('Failed to delete backup:', err);
    }
  };

  const downloadBackup = (filename) => {
    // Create a temporary link to trigger download
    const url = `${PUBLIC_API_BASE_URL}/api/admin/console/backups/${encodeURIComponent(filename)}/download`;
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const validateRestore = async (filename, passphrase = null, useEnvKey = false) => {
    selectedBackupForRestore = filename;
    if (!passphrase && !useEnvKey) {
      // Initial validation - reset state
      restoreValidation = null;
      restoreConfirmationPending = false;
    }

    try {
      const headers = {
        'Content-Type': 'application/json',
        accept: 'application/json'
      };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }

      const requestBody = { filename };
      if (passphrase) {
        requestBody.passphrase = passphrase;
      }
      if (useEnvKey) {
        requestBody.use_env_key = true;
      }

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/restore/validate`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        restoreValidation = await response.json();
      } else {
        const err = await response.json();
        backupError = err.error || 'Failed to validate backup';
        if (!passphrase && !useEnvKey) {
          selectedBackupForRestore = null;
        }
      }
    } catch (err) {
      backupError = 'Failed to connect to server';
      if (!passphrase && !useEnvKey) {
        selectedBackupForRestore = null;
      }
      console.error('Failed to validate restore:', err);
    }
  };

  const revalidateWithPassphrase = async () => {
    if (!selectedBackupForRestore) return;
    backupError = '';
    await validateRestore(selectedBackupForRestore, restorePassphrase, restoreUseEnvKey);
  };

  const cancelRestore = () => {
    selectedBackupForRestore = null;
    restoreValidation = null;
    restoreConfirmationPending = false;
    restoreDbOnly = false;
    restorePhotosOnly = false;
    restoreSkipPreBackup = false;
    restorePassphrase = '';
    restoreUseEnvKey = false;
  };

  const confirmRestore = () => {
    restoreConfirmationPending = true;
  };

  const startRestore = async () => {
    if (!selectedBackupForRestore) return;

    // Validate passphrase if backup is encrypted and not using env key
    const isEncrypted = restoreValidation?.encrypted;
    if (isEncrypted && !restoreUseEnvKey && !restorePassphrase) {
      backupError = 'Please enter the passphrase to decrypt this backup';
      return;
    }

    restoreInProgress = true;
    restoreCurrentStep = 'Starting restore...';
    restoreProgress = 0;
    backupError = '';
    backupNotice = '';

    try {
      const headers = {
        'Content-Type': 'application/json',
        accept: 'application/json'
      };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }

      const requestBody = {
        filename: selectedBackupForRestore,
        confirmation_token: 'RESTORE',
        db_only: restoreDbOnly,
        photos_only: restorePhotosOnly,
        skip_pre_backup: restoreSkipPreBackup
      };

      // Include decryption params if backup is encrypted
      if (isEncrypted) {
        if (restoreUseEnvKey) {
          requestBody.use_env_key = true;
        } else {
          requestBody.passphrase = restorePassphrase;
        }
      }

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/restore`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        const result = await response.json();
        currentRestoreId = result.restore_id;
        restoreConfirmationPending = false;
        pollRestoreStatus();
      } else {
        const err = await response.json();
        backupError = err.error || 'Failed to start restore';
        restoreInProgress = false;
      }
    } catch (err) {
      backupError = 'Failed to connect to server';
      restoreInProgress = false;
      console.error('Failed to start restore:', err);
    }
  };

  const pollRestoreStatus = async () => {
    if (!currentRestoreId) return;

    try {
      const headers = { accept: 'application/json' };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }

      const response = await fetch(
        `${PUBLIC_API_BASE_URL}/api/admin/console/restore/${currentRestoreId}/status`,
        { credentials: 'include', headers }
      );

      if (response.ok) {
        const result = await response.json();
        restoreProgress = result.progress || 0;
        restoreCurrentStep = result.current_step || '';

        if (result.status === 'completed') {
          restoreInProgress = false;
          backupNotice = 'Restore completed successfully! You may need to refresh the page.';
          currentRestoreId = null;
          selectedBackupForRestore = null;
          restoreValidation = null;
        } else if (result.status === 'failed') {
          restoreInProgress = false;
          backupError = result.error || 'Restore failed';
          currentRestoreId = null;
        } else {
          setTimeout(pollRestoreStatus, 1000);
        }
      }
    } catch (err) {
      console.error('Failed to poll restore status:', err);
      setTimeout(pollRestoreStatus, 2000);
    }
  };

  // Load backups when backup tab is selected (only once)
  $: if (activeTab === 'backup' && !backupsLoaded && !backupLoading) {
    loadBackups();
  }

  // Load encryption config when backup tab is selected
  $: if (activeTab === 'backup' && !encryptionConfigLoaded) {
    loadEncryptionConfig();
  }

  // ============================================================================
  // Legal Pages Functions
  // ============================================================================

  // Static fallback content - matches what's shown on public pages when DB is empty
  const staticFallbackContent = {
    privacy_policy: {
      title: 'Privacy Policy',
      content: `<h2>1. Introduction</h2>
<p>Welcome to Canvas and Clay. We respect your privacy and are committed to protecting your personal data. This privacy policy will inform you as to how we look after your personal data when you visit our website and tell you about your privacy rights.</p>

<h2>2. The Data We Collect</h2>
<p>We may collect, use, store and transfer different kinds of personal data about you which we have grouped together follows:</p>
<ul>
<li><strong>Identity Data:</strong> includes first name, last name, username or similar identifier.</li>
<li><strong>Contact Data:</strong> includes email address.</li>
<li><strong>Content Data:</strong> includes the photos, artwork images, and descriptions you upload to the platform.</li>
<li><strong>Technical Data:</strong> includes internet protocol (IP) address, browser type and version, time zone setting and location, and operating system.</li>
</ul>

<h2>3. How We Use Your Data</h2>
<p>We will only use your personal data when the law allows us to. Most commonly, we will use your personal data in the following circumstances:</p>
<ul>
<li>To register you as a new customer or artist.</li>
<li>To manage and display your artwork portfolio.</li>
<li>To manage our relationship with you (including notifying you about changes to our terms or privacy policy).</li>
<li>To administer and protect our business and this website.</li>
</ul>

<h2>4. Data Security</h2>
<p>We have put in place appropriate security measures to prevent your personal data from being accidentally lost, used, or accessed in an unauthorized way. We limit access to your personal data to those employees, agents, contractors, and other third parties who have a business need to know.</p>

<h2>5. Your Legal Rights</h2>
<p>Under certain circumstances, you have rights under data protection laws in relation to your personal data, including the right to request access, correction, erasure, restriction, transfer, to object to processing, to portability of data and (where the lawful ground of processing is consent) to withdraw consent.</p>

<h2>6. Contact Us</h2>
<p>If you have any questions about this privacy policy or our privacy practices, please contact us through the administrative channels on the platform.</p>`
    },
    terms_of_service: {
      title: 'Terms of Service',
      content: `<h2>1. Agreement to Terms</h2>
<p>These Terms of Service ("Terms") constitute a legally binding agreement between you ("you") and Canvas and Clay ("Canvas and Clay," "we," "us," or "our") concerning your access to and use of the Canvas and Clay website and any related media form, media channel, mobile website, or mobile application (collectively, the "Site").</p>
<p>By accessing or using the Site, you represent that you have read, understood, and agree to be bound by these Terms. If you do not agree, you must not use the Site.</p>

<h2>2. Changes to Terms</h2>
<p>We may update or revise these Terms from time to time. The "Last updated" date above reflects the most recent version. Your continued use of the Site after any revisions constitutes your acceptance of the updated Terms. If you do not agree to the new Terms, you must stop using the Site.</p>

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

<h2>4. User Eligibility and Account Responsibilities</h2>
<p>By using the Site, you represent and warrant that:</p>
<ol>
<li>You are at least 18 years old (or the age of majority in your jurisdiction).</li>
<li>Any registration information you submit is truthful, current, and complete.</li>
<li>You will maintain the confidentiality of your login credentials and are responsible for all activity under your account.</li>
<li>You will comply with all applicable laws and these Terms.</li>
</ol>
<p>We reserve the right to refuse service, suspend accounts, or remove content at our sole discretion.</p>

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

<h2>6. Termination</h2>
<p>We may suspend or terminate your access to all or part of the Site, or remove any Artist Content or user content, at any time and for any reason, including for violations of these Terms, without notice or liability.</p>
<p>Upon termination:</p>
<ul>
<li>your right to use the Site ends immediately;</li>
<li>we may retain certain data as required for legal, security, or operational reasons.</li>
</ul>

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

<h2>8. Limitation of Liability</h2>
<p>To the fullest extent permitted by law, Canvas and Clay and its officers, directors, employees, and agents shall not be liable for:</p>
<ul>
<li>any indirect, incidental, consequential, special, punitive, or exemplary damages;</li>
<li>loss of profits, data, goodwill, or other intangible losses;</li>
<li>any damages arising from your use or inability to use the Site.</li>
</ul>
<p>Our total liability for any claim shall not exceed: (a) the amount you paid to us (if any) in the last twelve months, or (b) $100, whichever is greater.</p>
<p>Some jurisdictions do not allow certain limitations; in such cases, our liability is limited to the maximum extent permitted by law.</p>

<h2>9. Indemnification</h2>
<p>You agree to defend, indemnify, and hold harmless Canvas and Clay and its officers, directors, employees, and agents from any claims, damages, liabilities, losses, and expenses (including attorneys' fees) arising out of:</p>
<ul>
<li>your use of the Site,</li>
<li>your Artist Content,</li>
<li>your violation of these Terms or applicable law.</li>
</ul>

<h2>10. Governing Law and Dispute Resolution</h2>
<p>These Terms are governed by the laws of the State of California, without regard to conflict of law principles.</p>
<p>Any legal action or proceeding shall be brought exclusively in the state or federal courts located in California, and you consent to personal jurisdiction in those courts.</p>

<h2>11. Privacy</h2>
<p>Your use of the Site is also governed by our Privacy Policy, which describes how we collect, use, disclose, and protect your information.</p>
<p>By using the Site, you consent to our data practices as described in the Privacy Policy.</p>

<h2>12. Miscellaneous</h2>
<ul>
<li>If any provision of these Terms is held invalid, the remaining provisions will remain in full force.</li>
<li>Our failure to enforce any right or provision does not constitute a waiver.</li>
<li>You may not assign these Terms; we may assign them without restriction.</li>
<li>These Terms constitute the entire agreement between you and Canvas and Clay regarding the Site.</li>
</ul>`
    }
  };

  const loadLegalPages = async () => {
    legalLoading = true;
    legalError = '';
    try {
      const headers = { accept: 'application/json' };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/legal-pages`, {
        credentials: 'include',
        headers
      });
      if (response.ok) {
        const result = await response.json();
        const fetchedPages = result.pages || [];

        // For each page type, use fetched data or fall back to static content
        for (const pageType of ['privacy_policy', 'terms_of_service']) {
          const fetchedPage = fetchedPages.find(p => p.page_type === pageType);
          if (fetchedPage && fetchedPage.content) {
            legalPages[pageType] = {
              title: fetchedPage.title,
              content: fetchedPage.content,
              last_updated: fetchedPage.last_updated,
              editor_email: fetchedPage.editor_email
            };
          } else {
            // Use static fallback - this is what the public page shows
            legalPages[pageType] = {
              title: staticFallbackContent[pageType].title,
              content: staticFallbackContent[pageType].content,
              last_updated: null,
              editor_email: null
            };
          }
        }

        legalPages = {...legalPages}; // Trigger reactivity
        // Initialize Quill with current page content using Quill's API
        if (quillEditor) {
          const currentPage = legalPages[legalActivePage];
          quillEditor.setContents([]);  // Clear first
          if (currentPage.content) {
            quillEditor.clipboard.dangerouslyPasteHTML(currentPage.content);
          }
        }
      } else {
        const err = await response.json();
        legalError = err.error || 'Failed to load legal pages';
      }
    } catch (err) {
      legalError = 'Failed to connect to server';
      console.error('Failed to load legal pages:', err);
    } finally {
      legalLoading = false;
      legalLoaded = true;
    }
  };

  const saveLegalPage = async () => {
    if (!quillEditor) return;

    legalSaving = true;
    legalError = '';
    legalNotice = '';

    const content = quillEditor.root.innerHTML;
    const title = legalPages[legalActivePage].title;

    try {
      const headers = {
        'Content-Type': 'application/json',
        accept: 'application/json'
      };
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
      }

      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/legal-pages/${legalActivePage}`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({ title, content })
      });

      if (response.ok) {
        await response.json();
        legalPages[legalActivePage].content = content;
        legalPages[legalActivePage].last_updated = new Date().toISOString();
        legalPages[legalActivePage].editor_email = $auth.user?.email || 'Unknown';
        legalPages = {...legalPages}; // Trigger reactivity
        legalNotice = 'Page saved successfully';
        setTimeout(() => legalNotice = '', 3000);
      } else {
        const err = await response.json();
        legalError = err.error || 'Failed to save page';
      }
    } catch (err) {
      legalError = 'Failed to connect to server';
      console.error('Failed to save legal page:', err);
    } finally {
      legalSaving = false;
    }
  };

  const initQuillEditor = () => {
    if (typeof window === 'undefined' || quillLoaded) return;

    // Load Quill CSS
    if (!document.querySelector('link[href*="quill.snow.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'https://cdn.jsdelivr.net/npm/quill@2.0.2/dist/quill.snow.css';
      document.head.appendChild(link);
    }

    // Load Quill JS
    if (!window.Quill && !document.querySelector('script[src*="quill"]')) {
      const script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/quill@2.0.2/dist/quill.js';
      script.onload = () => {
        createQuillInstance();
      };
      document.body.appendChild(script);
    } else if (window.Quill) {
      createQuillInstance();
    }
  };

  const createQuillInstance = () => {
    const editorEl = document.getElementById('legal-editor');
    if (!editorEl || quillEditor) return;

    // Register custom clipboard to handle pasted plain text with Unicode bullets
    const Clipboard = window.Quill.import('modules/clipboard');

    class PlainTextClipboard extends Clipboard {
      convert(html) {
        if (typeof html === 'string') {
          // Convert Unicode bullet points to HTML list items
          // First, wrap bullet lists
          let inBulletList = false;
          let inNumberedList = false;
          const lines = html.split('\n');
          const processed = [];

          for (let i = 0; i < lines.length; i++) {
            let line = lines[i];
            const bulletMatch = line.match(/^[\s]*[•*-]\s+(.+)$/);
            const numberedMatch = line.match(/^[\s]*\d+\.\s+(.+)$/);

            if (bulletMatch) {
              if (!inBulletList) {
                if (inNumberedList) { processed.push('</ol>'); inNumberedList = false; }
                processed.push('<ul>');
                inBulletList = true;
              }
              processed.push(`<li>${bulletMatch[1]}</li>`);
            } else if (numberedMatch) {
              if (!inNumberedList) {
                if (inBulletList) { processed.push('</ul>'); inBulletList = false; }
                processed.push('<ol>');
                inNumberedList = true;
              }
              processed.push(`<li>${numberedMatch[1]}</li>`);
            } else {
              if (inBulletList) { processed.push('</ul>'); inBulletList = false; }
              if (inNumberedList) { processed.push('</ol>'); inNumberedList = false; }

              // Convert horizontal lines (⸻ or ---) to <hr>
              if (/^[\s]*[⸻—-]{3,}[\s]*$/.test(line)) {
                processed.push('<hr>');
              } else if (line.trim()) {
                // Check if it looks like a heading (e.g., "1. Agreement to Terms")
                const headingMatch = line.match(/^(\d+)\.\s+(.+)$/);
                if (headingMatch && !line.includes('•') && lines[i+1]?.trim() === '') {
                  processed.push(`<h2>${line}</h2>`);
                } else {
                  processed.push(`<p>${line}</p>`);
                }
              }
              // Skip empty lines - don't add empty paragraphs
            }
          }

          if (inBulletList) processed.push('</ul>');
          if (inNumberedList) processed.push('</ol>');

          html = processed.join('');
        }
        return super.convert(html);
      }
    }

    window.Quill.register('modules/clipboard', PlainTextClipboard, true);

    quillEditor = new window.Quill('#legal-editor', {
      theme: 'snow',
      modules: {
        toolbar: [
          [{ header: [1, 2, 3, false] }],
          ['bold', 'italic', 'underline'],
          [{ list: 'ordered' }, { list: 'bullet' }],
          ['link'],
          ['clean']
        ],
        clipboard: {
          matchVisual: false
        }
      },
      placeholder: 'Enter page content...'
    });

    quillLoaded = true;

    // Load current page content using Quill's API
    const currentPage = legalPages[legalActivePage];
    if (currentPage.content) {
      quillEditor.clipboard.dangerouslyPasteHTML(currentPage.content);
    }
  };

  const switchLegalPage = (pageType) => {
    // Save current content to state before switching
    if (quillEditor) {
      legalPages[legalActivePage].content = quillEditor.root.innerHTML;
    }

    legalActivePage = pageType;

    // Load new page content into editor using Quill's API
    if (quillEditor) {
      const newPage = legalPages[pageType];
      quillEditor.setContents([]);  // Clear first
      if (newPage.content) {
        quillEditor.clipboard.dangerouslyPasteHTML(newPage.content);
      }
    }
  };

  const resetToDefault = () => {
    if (!quillEditor) return;
    const defaultContent = staticFallbackContent[legalActivePage];
    legalPages[legalActivePage].title = defaultContent.title;
    legalPages[legalActivePage].content = defaultContent.content;
    legalPages = {...legalPages};
    quillEditor.setContents([]);
    quillEditor.clipboard.dangerouslyPasteHTML(defaultContent.content);
    legalNotice = 'Reset to default content. Remember to save.';
    setTimeout(() => legalNotice = '', 3000);
  };

  const formatLegalDate = (isoString) => {
    if (!isoString) return 'Never';
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Load legal pages when legal tab is selected (only once)
  $: if (activeTab === 'legal' && !legalLoaded && !legalLoading) {
    loadLegalPages();
  }

  // Initialize Quill when legal tab becomes active
  $: if (activeTab === 'legal' && legalLoaded && !quillLoaded) {
    // Use setTimeout to ensure DOM is ready
    setTimeout(initQuillEditor, 100);
  }

  // Cleanup intervals on component destroy
  onDestroy(() => {
    stopPeriodicApiCheck();
    stopAlertPolling();
    if (timeUpdateInterval) {
      clearInterval(timeUpdateInterval);
      timeUpdateInterval = null;
    }
    if (apiCheckInterval) {
      clearInterval(apiCheckInterval);
      apiCheckInterval = null;
    }
    // Remove visibility change listener
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    }
  });
</script>

<div class="console-container">
  <h1>Admin Console</h1>

  {#if isLoading}
    <div class="loading">Loading console data...</div>
  {:else if loadError && (!stats && !health)}
    <div class="error-message">
      {loadError}
      {#if loadError === 'Access denied: Admin role required' || loadError === 'Authentication required'}
        <div style="margin-top: 1rem;">
          <a href="/login">Go to Login</a> | <a href="/">Go to Home</a>
        </div>
      {/if}
    </div>
  {:else if !stats && !health}
    <div class="loading">Failed to load data</div>
  {:else}

  <div class="tabs">
    <button
      class:active={activeTab === 'overview'}
      on:click={() => handleTabChange('overview')}
    >
      Overview
    </button>
    <button
      class:active={activeTab === 'security'}
      on:click={() => handleTabChange('security')}
    >
      Security
    </button>
    <button
      class:active={activeTab === 'requests'}
      on:click={() => handleTabChange('requests')}
    >
      Reset Requests
    </button>
    <button
      class:active={activeTab === 'users'}
      on:click={() => handleTabChange('users')}
    >
      Users
    </button>
    <button
      class:active={activeTab === 'database'}
      on:click={() => handleTabChange('database')}
    >
      Database
    </button>
    <button
      class:active={activeTab === 'cli'}
      on:click={() => handleTabChange('cli')}
    >
      CLI
    </button>
    <button
      class:active={activeTab === 'backup'}
      on:click={() => handleTabChange('backup')}
    >
      Backup
    </button>
    <button
      class:active={activeTab === 'legal'}
      on:click={() => handleTabChange('legal')}
    >
      Legal
    </button>
  </div>

  <div class="tab-content">
    {#if activeTab === 'overview'}
      <div class="overview">
        <div class="health-status">
          <h2>System Health</h2>
          <div class="status-badge" class:healthy={overallHealthStatus === 'healthy'}>
            {overallHealthStatus}
          </div>
        </div>

        <div class="api-test-section">
          <div class="api-test-header">
            <h3>API Connection Test</h3>
            <button 
              on:click={testApiConnection} 
              disabled={apiTestLoading}
              class="test-api-btn"
            >
              {apiTestLoading ? 'Testing...' : 'Test API Connection'}
            </button>
          </div>
          
          {#if apiTestResult}
            <div class="api-test-result" class:success={apiTestResult.success} class:error={!apiTestResult.success}>
              {#if apiTestResult.success}
                <p><strong>Success:</strong> {apiTestResult.message}</p>
              {:else}
                <p><strong>Error:</strong> {apiTestResult.message}</p>
              {/if}
            </div>
          {/if}
          
          {#if lastApiCheck}
            <div class="last-check">
              Last checked: {timeAgoDisplay}
            </div>
          {/if}
          
            <div class="periodic-check-info">
              <p>Automatic health checks run every 60 seconds while this tab is open.</p>
              {#if isRateLimited && rateLimitRetryAfter}
                <p class="rate-limit-warning">Rate limited. Health checks paused for {rateLimitRetryAfter} seconds.</p>
              {/if}
            </div>
        </div>

        <div class="info-section">
          <h3>Backend Health Details</h3>
          <div><strong>Database Status:</strong> {health?.database?.status || 'unknown'}</div>
          <div><strong>Database Engine:</strong> {health?.database?.engine || 'unknown'}</div>
          <div><strong>Environment:</strong> {health?.environment || 'unknown'}</div>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Artworks</div>
            <div class="stat-value">{stats?.counts?.artworks || 0}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Artists</div>
            <div class="stat-value">{stats?.counts?.artists || 0}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Photos</div>
            <div class="stat-value">{stats?.counts?.photos || 0}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Users</div>
            <div class="stat-value">{stats?.counts?.users || 0}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Pending Reset Requests</div>
            <div class="stat-value">{stats?.counts?.password_reset_pending || 0}</div>
          </div>
        </div>

        <div class="recent-activity">
          <h2>Recent Activity (Last 24h)</h2>
          <div class="activity-list">
            <div>New Artworks: {stats?.recent_activity?.artworks_last_24h || 0}</div>
            <div>New Photos: {stats?.recent_activity?.photos_last_24h || 0}</div>
            <div>New Users: {stats?.recent_activity?.users_last_24h || 0}</div>
            <div>Failed Logins: {stats?.recent_activity?.failed_logins_last_24h || 0}</div>
            <div>Password Reset Requests: {stats?.recent_activity?.password_resets_last_24h || 0}</div>
          </div>
        </div>
      </div>
    {:else if activeTab === 'security'}
      <div class="security">
        <h2>Audit Logs</h2>
        {#if alertLogs.length > 0}
          <div class="inline-info alert-box">
            <div class="alert-header">
              <strong>Security alerts</strong>
              <span class="alert-subtext">Recent spikes and role changes</span>
            </div>
            <div class="alert-grid">
              {#each alertLogs as log}
                <div class="alert-row">
                  <div class="alert-row-main">
                    <span class="pill pill-alert">{log.event_type}</span>
                    <span class="alert-meta">{formatDate(log.created_at)}</span>
                  </div>
                  {#if log.details}
                    <div class="alert-details">{log.details}</div>
                  {/if}
                </div>
              {/each}
            </div>
            <div class="alert-actions">
              <div class="alert-action-list">
                <div><strong>Recommended actions:</strong></div>
                <ul>
                  <li>Lock or reset accounts involved in unexpected promotions/demotions.</li>
                  <li>Review recent audit logs for suspicious activity.</li>
                  <li>Force logout active sessions if abuse is suspected.</li>
                  <li>Consider temporarily restricting role changes or uploads.</li>
                </ul>
              </div>
              <div class="alert-buttons">
                <button class="secondary" on:click={() => loadAlertLogs()}>Refresh alerts</button>
                <button class="secondary" on:click={clearAlerts}>Mark as reviewed</button>
              </div>
              {#if alertActionsMessage}
                <div class="inline-info small">{alertActionsMessage}</div>
              {/if}
            </div>
          </div>
        {:else if alertReviewState?.reviewedAt}
          <div class="inline-info alert-box">
            <div class="alert-header">
              <strong>Alerts marked as reviewed.</strong>
              <span class="alert-subtext">New alerts will appear automatically when triggered.</span>
            </div>
            <div class="inline-info small">
              {alertActionsMessage ||
                'Alerts marked as reviewed. New alerts will appear automatically when triggered.'}
            </div>
          </div>
        {/if}
        <div class="filters">
          <input
            type="text"
            bind:value={auditLogEventType}
            placeholder="Filter by event type..."
            on:keydown={(e) => e.key === 'Enter' && handleAuditLogFilter()}
          />
          <button on:click={handleAuditLogFilter}>Filter</button>
        </div>
        <div class="cleanup-card">
          <div class="cleanup-row">
            <label for="audit-cleanup-days">Delete audit logs older than</label>
            <input
              id="audit-cleanup-days"
              type="number"
              min="0"
              bind:value={cleanup.auditDays}
              aria-label="Audit log retention days"
            />
            <span>days (0 = delete all)</span>
            <button
              class="secondary"
              on:click={cleanupAuditLogs}
              disabled={cleanup.auditLoading}
            >
              {cleanup.auditLoading ? 'Cleaning...' : 'Cleanup'}
            </button>
          </div>
          {#if cleanup.auditMessage}
            <div class="inline-info small">{cleanup.auditMessage}</div>
          {/if}
        </div>
        {#if loading.auditLog}
          <div>Loading...</div>
        {:else}
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Event Type</th>
                <th>Email</th>
                <th>IP Address</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              {#each auditLogs as log}
                <tr>
                  <td>{log.id}</td>
                  <td>{log.event_type}</td>
                  <td>{log.email || '-'}</td>
                  <td>{log.ip_address}</td>
                  <td>{formatDate(log.created_at)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if auditLogPagination}
            <div class="pagination">
              <button
                disabled={auditLogPage === 1}
                on:click={() => loadAuditLogs(auditLogPage - 1, auditLogEventType)}
              >
                Previous
              </button>
              <span>Page {auditLogPage} of {auditLogPagination.pages}</span>
              <button
                disabled={auditLogPage >= auditLogPagination.pages}
                on:click={() => loadAuditLogs(auditLogPage + 1, auditLogEventType)}
              >
                Next
              </button>
            </div>
          {/if}
        {/if}

        <h2>Failed Login Attempts</h2>
          <div class="cleanup-card">
            <div class="cleanup-row">
              <label for="failed-cleanup-days">Delete failed logins older than</label>
              <input
                id="failed-cleanup-days"
              type="number"
              min="0"
              bind:value={cleanup.failedDays}
              aria-label="Failed login retention days"
            />
            <span>days (0 = delete all)</span>
            <button
              class="secondary"
              on:click={cleanupFailedLogins}
              disabled={cleanup.failedLoading}
            >
              {cleanup.failedLoading ? 'Cleaning...' : 'Cleanup'}
            </button>
            </div>
            {#if cleanup.failedMessage}
              <div class="inline-info small">{cleanup.failedMessage}</div>
            {/if}
          </div>
          <div class="purge-card">
            <label for="purge-days">Permanently delete users soft-deleted more than</label>
            <input
              id="purge-days"
              type="number"
              min="0"
              bind:value={purgeDays}
              aria-label="Purge deleted users older than days"
            />
            <span>days (0 = delete all soft-deleted)</span>
            <button
              class="secondary"
              disabled={userActionLoading['__purge__']}
              on:click={purgeDeletedUsers}
            >
              {userActionLoading['__purge__'] ? 'Purging...' : 'Purge deleted users'}
            </button>
          </div>
          {#if purgeMessage}
            <div class="inline-info small">{purgeMessage}</div>
          {/if}
        {#if loading.failedLogins}
          <div>Loading...</div>
        {:else}
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Email</th>
                <th>IP Address</th>
                <th>Attempted At</th>
              </tr>
            </thead>
            <tbody>
              {#each failedLogins as attempt}
                <tr>
                  <td>{attempt.id}</td>
                  <td>{attempt.email}</td>
                  <td>{attempt.ip_address}</td>
                  <td>{formatDate(attempt.attempted_at)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if failedLoginsPagination}
            <div class="pagination">
              <button
                disabled={failedLoginsPage === 1}
                on:click={() => loadFailedLogins(failedLoginsPage - 1)}
              >
                Previous
              </button>
              <span>Page {failedLoginsPage} of {failedLoginsPagination.pages}</span>
              <button
                disabled={failedLoginsPage >= failedLoginsPagination.pages}
                on:click={() => loadFailedLogins(failedLoginsPage + 1)}
              >
                Next
              </button>
            </div>
          {/if}
        {/if}
      </div>
    {:else if activeTab === 'requests'}
      <div class="password-reset-tab">
        <div class="reset-header">
          <div>
            <h2>Password Reset Requests</h2>
            <p class="reset-subtitle">Manual approvals, denials, and admin notes</p>
          </div>
          <div class="reset-controls">
            <label for="reset-filter">
              Status
              <select
                id="reset-filter"
                bind:value={passwordResetFilter}
                on:change={() => loadPasswordResetRequests(1, passwordResetFilter)}
              >
                <option value="pending">Pending</option>
                <option value="approved">Approved</option>
                <option value="denied">Denied</option>
                <option value="completed">Completed</option>
                <option value="expired">Expired</option>
                <option value="all">All</option>
              </select>
            </label>
            <button
              class="secondary"
              on:click={() => loadPasswordResetRequests(passwordResetPage, passwordResetFilter)}
              disabled={passwordResetLoading}
            >
              {passwordResetLoading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>
        {#if passwordResetNotice}
          <div class="inline-info small">{passwordResetNotice}</div>
        {/if}
        {#if passwordResetError}
          <div class="inline-error">{passwordResetError}</div>
        {/if}
        {#if passwordResetLoading}
          <div>Loading reset requests...</div>
        {:else if passwordResetRequests.length === 0}
          <div class="inline-info">No password reset requests found for this filter.</div>
        {:else}
          <div class="reset-grid">
            {#each passwordResetRequests as reset}
              <div class="reset-card">
                <div class="reset-card-header">
                  <div>
                    <div class="reset-email">{reset.email}</div>
                    <div class="reset-meta">Requested {formatDate(reset.created_at)}</div>
                    {#if reset.user_id}
                      <div class="reset-meta">User ID: {reset.user_id}</div>
                    {/if}
                  </div>
                  <span class={`pill pill-${reset.status}`}>{reset.status}</span>
                </div>
                {#if reset.user_message}
                  <div class="reset-message">
                    <strong>User:</strong> {reset.user_message}
                  </div>
                {/if}
                {#if reset.admin_message}
                  <div class="reset-message admin">
                    <strong>Admin:</strong> {reset.admin_message}
                  </div>
                {/if}
                {#if reset.status === 'approved'}
                  <div class="reset-meta">
                    Expires {reset.expires_at ? formatDate(reset.expires_at) : '—'}
                  </div>
                  <div class="reset-meta hint">Reset codes expire 15 minutes after approval. Share the code with the requester promptly.</div>
                  {#if passwordResetCodes[reset.id]}
                    <div class="code-banner">
                      Latest reset code: <code>{passwordResetCodes[reset.id]}</code>
                    </div>
                    <div class="reset-meta hint">Share this code securely with the requester.</div>
                  {:else if reset.code_hint}
                    <div class="reset-meta hint">Code hint: ends with {reset.code_hint}</div>
                  {/if}
                {:else if reset.status === 'expired'}
                  <div class="reset-meta" style="color: var(--error-color, #c5221f);">
                    This reset code has expired. The requester will need a new code.
                  </div>
                {:else if reset.resolved_at}
                  <div class="reset-meta">
                    Resolved {reset.resolved_at ? formatDate(reset.resolved_at) : ''}
                  </div>
                {/if}
                <label class="reset-note-label" for={`reset-note-${reset.id}`}>
                  Admin message
                </label>
                <textarea
                  id={`reset-note-${reset.id}`}
                  rows="2"
                  value={passwordResetAdminNotes[reset.id] || ''}
                  on:input={(e) => {
                    passwordResetAdminNotes = {
                      ...passwordResetAdminNotes,
                      [reset.id]: e.currentTarget.value
                    };
                  }}
                  placeholder="Add a note for the requester or audit log (optional)"
                  disabled={isResetActionPending(reset.id)}
                ></textarea>
                <div class="reset-card-actions">
                  {#if reset.status === 'pending'}
                    <button
                      class="primary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => approvePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-approve`] ? 'Generating...' : 'Approve & generate code'}
                    </button>
                    <button
                      class="danger"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => denyPasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-deny`] ? 'Working...' : 'Deny'}
                    </button>
                    <button
                      class="secondary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => deletePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-delete`] ? 'Deleting...' : 'Delete'}
                    </button>
                  {:else if reset.status === 'approved'}
                    <button
                      class="primary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => approvePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-approve`] ? 'Generating...' : 'Generate new code'}
                    </button>
                    <button
                      class="secondary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => completePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-complete`] ? 'Marking...' : 'Mark completed'}
                    </button>
                    <button
                      class="danger"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => denyPasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-deny`] ? 'Working...' : 'Deny'}
                    </button>
                    <button
                      class="secondary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => deletePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-delete`] ? 'Deleting...' : 'Delete'}
                    </button>
                  {:else if reset.status === 'denied' || reset.status === 'expired'}
                    <button
                      class="primary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => approvePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-approve`] ? 'Re-opening...' : 'Re-open & generate code'}
                    </button>
                    <button
                      class="secondary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => deletePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-delete`] ? 'Deleting...' : 'Delete'}
                    </button>
                  {:else}
                    <button
                      class="primary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => approvePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-approve`] ? 'Generating...' : 'Generate new code'}
                    </button>
                    <button
                      class="secondary"
                      disabled={isResetActionPending(reset.id)}
                      on:click={() => deletePasswordReset(reset)}
                    >
                      {passwordResetActionLoading[`${reset.id}-delete`] ? 'Deleting...' : 'Delete'}
                    </button>
                  {/if}
                </div>
              </div>
            {/each}
          </div>
          {#if passwordResetPagination}
            <div class="pagination">
              <button
                disabled={passwordResetPage === 1}
                on:click={() => loadPasswordResetRequests(passwordResetPage - 1, passwordResetFilter)}
              >
                Previous
              </button>
              <span>
                Page {passwordResetPagination?.page || passwordResetPage} of {passwordResetPagination?.pages || 1}
              </span>
              <button
                disabled={
                  passwordResetPagination?.pages
                    ? passwordResetPage >= passwordResetPagination.pages
                    : passwordResetRequests.length < 10
                }
                on:click={() => loadPasswordResetRequests(passwordResetPage + 1, passwordResetFilter)}
              >
                Next
              </button>
            </div>
          {/if}
        {/if}
      </div>
    {:else if activeTab === 'users'}
      <div class="users">
        <h2>Users</h2>
        {#if userRoleCounts}
          <div class="user-summary">
            <span><strong>Admins:</strong> {userRoleCounts.admin || 0}</span>
            <span><strong>Artists:</strong> {userRoleCounts.artist || 0}</span>
            <span><strong>Guests:</strong> {userRoleCounts.guest || 0}</span>
            <span><strong>Inactive:</strong> {userRoleCounts.inactive || 0}</span>
          </div>
        {/if}
        {#if users.find((u) => u.is_bootstrap_admin)}
          <div class="inline-info">
            The bootstrap admin account cannot be promoted, demoted, or deactivated. Keep it as a recovery account.
          </div>
        {/if}
        {#if userActionError}
          <div class="inline-error">{userActionError}</div>
        {/if}
        {#if userActionNotice}
          <div class="inline-info small">{userActionNotice}</div>
        {/if}
        {#if loading.users}
          <div>Loading...</div>
        {:else}
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created At</th>
                <th>Last Login</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each users as user}
                <tr>
                  <td>{user.id}</td>
                  <td>
                    <div class="user-email">{user.email}</div>
                    {#if !user.is_active}
                      <span class="pill pill-muted">Inactive</span>
                    {/if}
                    {#if user.is_bootstrap_admin}
                      <span class="pill pill-warning">Bootstrap admin</span>
                    {/if}
                    {#if user.deleted_at}
                      <span class="pill pill-danger">Pending deletion</span>
                    {/if}
                  </td>
                  <td><span class={`pill pill-${user.role?.replace(' ', '-')}`}>{user.role}</span></td>
                  <td>
                    {#if user.deleted_at}
                      Pending deletion
                    {:else}
                      {user.is_active ? 'Active' : 'Inactive'}
                    {/if}
                  </td>
                  <td>{formatDate(user.created_at)}</td>
                  <td>{formatDate(user.last_login)}</td>
                  <td>
                    <div class="user-actions">
                      <button
                        class="secondary"
                        disabled={
                          user.role === 'guest' ||
                          userActionLoading[user.id] ||
                          $auth.user?.id === user.id ||
                          user.is_bootstrap_admin
                        }
                        on:click={() => demoteUser(user)}
                        aria-label={`Demote ${user.email}`}
                      >
                        {userActionLoading[user.id] ? 'Working...' : 'Demote'}
                      </button>
                      <button
                        class="secondary"
                        disabled={user.role === 'admin' || userActionLoading[user.id]}
                        on:click={() => promoteUser(user)}
                        aria-label={`Promote ${user.email}`}
                      >
                        {userActionLoading[user.id] ? 'Working...' : 'Promote'}
                      </button>
                      <button
                        class={user.is_active ? 'danger' : 'secondary'}
                        disabled={
                          userActionLoading[user.id] ||
                          $auth.user?.id === user.id ||
                          user.is_bootstrap_admin ||
                          user.deleted_at
                        }
                        on:click={() => toggleUserActive(user)}
                        aria-label={`${user.is_active ? 'Deactivate' : 'Reactivate'} ${user.email}`}
                      >
                        {#if userActionLoading[user.id]}
                          Working...
                        {:else}
                          {user.is_active ? 'Deactivate' : 'Reactivate'}
                        {/if}
                      </button>
                      <button
                        class="secondary"
                        disabled={
                          userActionLoading[user.id] ||
                          $auth.user?.id === user.id ||
                          user.is_bootstrap_admin ||
                          user.deleted_at
                        }
                        on:click={() => forceLogoutUser(user)}
                        aria-label={`Force logout ${user.email}`}
                      >
                        {userActionLoading[user.id] ? 'Working...' : 'Force logout'}
                      </button>
                      <button
                        class="secondary"
                        disabled={
                          userActionLoading[user.id] ||
                          user.is_bootstrap_admin ||
                          user.deleted_at
                        }
                        on:click={() => softDeleteUser(user)}
                        aria-label={`Soft delete ${user.email}`}
                      >
                        {userActionLoading[user.id] ? 'Working...' : 'Delete'}
                      </button>
                      {#if user.deleted_at}
                        <button
                          class="secondary"
                          disabled={userActionLoading[user.id]}
                          on:click={() => restoreUser(user)}
                          aria-label={`Restore ${user.email}`}
                        >
                          {userActionLoading[user.id] ? 'Working...' : 'Restore'}
                        </button>
                        <button
                          class="danger"
                          disabled={
                            userActionLoading[user.id] ||
                            user.is_bootstrap_admin ||
                            $auth.user?.id === user.id
                          }
                          on:click={() => hardDeleteUser(user)}
                          aria-label={`Permanently delete ${user.email}`}
                        >
                          {userActionLoading[user.id] ? 'Working...' : 'Delete permanently'}
                        </button>
                      {/if}
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}

        <div class="artist-assignments">
          <div class="artist-assignments-header">
            <h3>Artist Assignments</h3>
            <p class="artist-assignments-description">Manage which artist profiles are linked to user accounts.</p>
          </div>
          {#if loadingArtists}
            <div class="loading-state">Loading artists...</div>
          {:else}
            <div class="assign-form">
              <div class="form-field">
                <label for="assign-user-select">User</label>
                <div class="select-wrapper">
                  <select id="assign-user-select" bind:value={assignUserId} class="form-select">
                    <option value="">Select user</option>
                    {#each users as u}
                      <option value={u.id}>{u.email} ({u.role})</option>
                    {/each}
                  </select>
                </div>
              </div>
              <div class="form-field">
                <label for="assign-artist-select">Artist</label>
                <div class="select-wrapper">
                  <select id="assign-artist-select" bind:value={assignArtistId} class="form-select">
                    <option value="">Select artist</option>
                    {#each artists as artist}
                      <option value={artist.id}>
                        {artist.id} — {artist.name}{artist.user_email ? ` (linked to ${artist.user_email})` : ' (unassigned)'}
                      </option>
                    {/each}
                  </select>
                </div>
              </div>
              <div class="assign-actions">
                <button class="assign-button primary" on:click={assignArtistToUser} disabled={!assignUserId || !assignArtistId}>
                  Assign
                </button>
                <button class="assign-button secondary" on:click={unassignArtist} disabled={!assignArtistId}>
                  Unassign
                </button>
              </div>
            </div>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'database'}
      <div class="database">
        <h2>Database Information</h2>
        {#if loading.database}
          <div>Loading...</div>
        {:else if databaseInfo}
          <div class="info-section">
            <h3>Engine</h3>
            <div><strong>Name:</strong> {databaseInfo.engine?.name || 'unknown'}</div>
            <div><strong>Database:</strong> {databaseInfo.engine?.database || 'unknown'}</div>
          </div>
          <h3>Table Row Counts</h3>
          <table>
            <thead>
              <tr>
                <th>Table</th>
                <th>Row Count</th>
              </tr>
            </thead>
            <tbody>
              {#each Object.entries(databaseInfo.table_counts || {}) as [table, count]}
                <tr>
                  <td>{table}</td>
                  <td>{count}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    {:else if activeTab === 'cli'}
      <div class="cli">
        <div class="cli-controls">
          <div class="write-mode-toggle">
            <label>
              <input type="checkbox" checked={writeMode} on:change={toggleWriteMode} />
              <span class:active={writeMode}>Write Mode</span>
            </label>
            {#if writeMode}
              <span class="write-mode-warning">Write operations enabled</span>
            {/if}
          </div>
          <button on:click={clearCLIOutput} class="clear-btn">Clear Output</button>
        </div>

        <form class="cli-input-area" on:submit|preventDefault={(e) => {
          e.preventDefault();
          executeCommand();
        }}>
          <div class="input-wrapper">
            <span class="prompt">&gt;</span>
            <input
              type="text"
              bind:this={commandInputElement}
              bind:value={commandInput}
              on:input={handleCommandInput}
              on:keydown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  e.stopPropagation();
                  executeCommand();
                  return false;
                } else if (e.key === 'ArrowUp') {
                  e.preventDefault();
                  e.stopPropagation();
                  if (historyIndex > 0) {
                    historyIndex--;
                    commandInput = commandHistory[historyIndex];
                  }
                  return false;
                } else if (e.key === 'ArrowDown') {
                  e.preventDefault();
                  e.stopPropagation();
                  if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    commandInput = commandHistory[historyIndex];
                  } else {
                    historyIndex = commandHistory.length;
                    commandInput = '';
                  }
                  return false;
                }
              }}
              placeholder="Enter command (type 'help' for available commands, 'clear' to clear output)"
              class:write-mode-active={writeMode}
            />
          </div>
        </form>

        {#if confirmationStep > 0}
          <div class="confirmation-warning" class:step1={confirmationStep === 1} class:step2={confirmationStep === 2}>
            {#if confirmationStep === 1}
              <p><strong>First Confirmation Required</strong></p>
              <p>This operation will delete data. Type the command again to confirm.</p>
            {:else if confirmationStep === 2}
              <p><strong>Final Confirmation Required</strong></p>
              <p>This action cannot be undone. Type the command one more time to proceed.</p>
            {/if}
          </div>
        {/if}

        <div class="cli-output" bind:this={cliOutputElement} on:scroll={handleCLIScroll}>
          {#each cliOutput as output}
            <div class="output-line" class:command={output.type === 'command'} class:success={output.type === 'success'} class:error={output.type === 'error'} class:warning={output.type === 'warning'} class:data={output.type === 'data'}>
              {#if output.type === 'command'}
                <span class="output-timestamp">[{output.timestamp}]</span>
              {/if}
              <pre>{output.text}</pre>
            </div>
          {/each}
          {#if cliOutput.length === 0}
            <div class="output-placeholder">
              <p>CLI ready. Type 'help' to see available commands.</p>
              <p>Type 'clear' or 'cls' to clear the output.</p>
              <p>Use ↑/↓ arrow keys to navigate command history.</p>
            </div>
          {/if}
        </div>
      </div>
    {:else if activeTab === 'backup'}
      <div class="backup-section">
        <h2>Backup & Restore</h2>

        {#if backupError}
          <div class="error-message">{backupError}</div>
        {/if}
        {#if backupNotice}
          <div class="success-message">{backupNotice}</div>
        {/if}

        <!-- Create Backup Section -->
        <div class="backup-create">
          <h3>Create New Backup</h3>
          <div class="backup-options">
            <label class="backup-option">
              <input type="radio" bind:group={backupDbOnly} value={false} on:change={() => { backupDbOnly = false; backupPhotosOnly = false; }} checked={!backupDbOnly && !backupPhotosOnly} />
              <span>Full Backup (Database + Photos)</span>
            </label>
            <label class="backup-option">
              <input type="radio" bind:group={backupDbOnly} value={true} on:change={() => { backupDbOnly = true; backupPhotosOnly = false; }} />
              <span>Database Only</span>
            </label>
            <label class="backup-option">
              <input type="radio" bind:group={backupPhotosOnly} value={true} on:change={() => { backupPhotosOnly = true; backupDbOnly = false; }} />
              <span>Photos Only</span>
            </label>
          </div>

          <div class="backup-extra-options">
            <label class="checkbox-option">
              <input type="checkbox" bind:checked={backupIncludeThumbnails} disabled={backupDbOnly} />
              <span>Include thumbnails</span>
            </label>
            <label class="checkbox-option">
              <input type="checkbox" bind:checked={backupExcludeAuditLogs} disabled={backupPhotosOnly} />
              <span>Exclude audit logs</span>
            </label>
          </div>

          <!-- Encryption Options -->
          <div class="backup-encryption-options">
            <label class="checkbox-option">
              <input type="checkbox" bind:checked={backupEncrypt} />
              <span>Encrypt backup (AES-256-GCM)</span>
            </label>

            {#if backupEncrypt}
              <div class="encryption-method">
                {#if envKeyConfigured}
                  <label class="checkbox-option">
                    <input type="checkbox" bind:checked={backupUseEnvKey} />
                    <span>Use server encryption key (recommended for automated backups)</span>
                  </label>
                {/if}

                {#if !backupUseEnvKey}
                  <div class="passphrase-inputs">
                    <div class="input-group">
                      <label for="backup-passphrase">Passphrase</label>
                      <input
                        id="backup-passphrase"
                        type="password"
                        bind:value={backupPassphrase}
                        placeholder="Enter passphrase (min 12 characters)"
                        autocomplete="new-password"
                      />
                    </div>
                    <div class="input-group">
                      <label for="backup-passphrase-confirm">Confirm Passphrase</label>
                      <input
                        id="backup-passphrase-confirm"
                        type="password"
                        bind:value={backupPassphraseConfirm}
                        placeholder="Confirm passphrase"
                        autocomplete="new-password"
                      />
                    </div>
                    <p class="passphrase-hint">
                      Must be at least 12 characters with uppercase, lowercase, and a number or symbol.
                    </p>
                  </div>
                {/if}
              </div>
            {/if}
          </div>

          <button
            class="primary backup-btn"
            on:click={startBackup}
            disabled={backupInProgress || (backupEncrypt && !backupUseEnvKey && (!backupPassphrase || backupPassphrase !== backupPassphraseConfirm))}
          >
            {backupInProgress ? 'Creating Backup...' : (backupEncrypt ? 'Create Encrypted Backup' : 'Create Backup')}
          </button>

          {#if backupInProgress}
            <div class="progress-container">
              <div class="progress-bar">
                <div class="progress-fill" style="width: {backupProgress}%"></div>
              </div>
              <div class="progress-text">{backupCurrentStep}</div>
            </div>
          {/if}
        </div>

        <!-- Available Backups Section -->
        <div class="backup-list-section">
          <div class="backup-list-header">
            <h3>Available Backups</h3>
            <button class="secondary" on:click={loadBackups} disabled={backupLoading}>
              {backupLoading ? 'Loading...' : 'Refresh'}
            </button>
          </div>

          {#if backupLoading && backups.length === 0}
            <div class="loading">Loading backups...</div>
          {:else if backups.length === 0}
            <div class="no-backups">No backups found. Create your first backup above.</div>
          {:else}
            <table class="backup-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Type</th>
                  <th>Size</th>
                  <th>Created</th>
                  <th>Contents</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {#each backups as backup}
                  <tr>
                    <td class="filename">{backup.filename}</td>
                    <td>
                      <span class="backup-type-badge" class:full={backup.type === 'full'} class:db={backup.type === 'db_only'} class:photos={backup.type === 'photos_only'}>
                        {backup.type === 'full' ? 'Full' : backup.type === 'db_only' ? 'DB' : backup.type === 'photos_only' ? 'Photos' : backup.type}
                      </span>
                      {#if backup.encrypted}
                        <span class="backup-encrypted-badge" title="AES-256-GCM encrypted">Encrypted</span>
                      {/if}
                    </td>
                    <td>{formatBytes(backup.size)}</td>
                    <td>{new Date(backup.created_at).toLocaleString()}</td>
                    <td>
                      {#if backup.has_database}DB{/if}
                      {#if backup.has_database && backup.has_photos} + {/if}
                      {#if backup.has_photos}{backup.photo_count} photos{/if}
                    </td>
                    <td class="actions">
                      <button class="action-btn download" on:click={() => downloadBackup(backup.filename)} title="Download">
                        Download
                      </button>
                      <button class="action-btn restore" on:click={() => validateRestore(backup.filename)} title="Restore" disabled={restoreInProgress}>
                        Restore
                      </button>
                      <button class="action-btn delete" on:click={() => deleteBackup(backup.filename)} title="Delete">
                        Delete
                      </button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>

        <!-- Restore Modal -->
        {#if selectedBackupForRestore && restoreValidation}
          <div class="restore-modal-backdrop" on:click={cancelRestore}>
            <div class="restore-modal" on:click|stopPropagation>
              <h3>Restore from Backup</h3>
              <p class="restore-filename">{selectedBackupForRestore}</p>

              {#if restoreValidation.requires_passphrase}
                <!-- Encrypted backup needs passphrase to validate -->
                <div class="restore-encryption-section">
                  <h4>Encrypted Backup</h4>
                  <p class="encryption-info">This backup is encrypted. Enter the passphrase to view details and restore.</p>

                  {#if envKeyConfigured}
                    <label class="checkbox-option">
                      <input type="checkbox" bind:checked={restoreUseEnvKey} />
                      <span>Use server encryption key</span>
                    </label>
                  {/if}

                  {#if !restoreUseEnvKey}
                    <div class="input-group">
                      <label for="restore-passphrase">Passphrase</label>
                      <input
                        id="restore-passphrase"
                        type="password"
                        bind:value={restorePassphrase}
                        placeholder="Enter the passphrase used to encrypt this backup"
                        autocomplete="current-password"
                      />
                    </div>
                  {/if}

                  <div class="restore-actions">
                    <button class="primary" on:click={revalidateWithPassphrase} disabled={!restoreUseEnvKey && !restorePassphrase}>
                      Unlock Backup
                    </button>
                    <button class="secondary" on:click={cancelRestore}>Cancel</button>
                  </div>
                </div>
              {:else}
                <!-- Full validation info available -->
                <div class="restore-info">
                  <div><strong>Type:</strong> {restoreValidation.manifest?.type || 'Unknown'}</div>
                  <div><strong>Created:</strong> {restoreValidation.manifest?.created_at ? new Date(restoreValidation.manifest.created_at).toLocaleString() : 'Unknown'}</div>
                  <div><strong>Created by:</strong> {restoreValidation.manifest?.created_by || 'Unknown'}</div>
                  {#if restoreValidation.encrypted}
                    <div><strong>Encrypted:</strong> Yes (AES-256-GCM)</div>
                  {/if}
                </div>

                {#if restoreValidation.warnings && restoreValidation.warnings.length > 0}
                  <div class="restore-warnings">
                    <strong>Warnings:</strong>
                    <ul>
                      {#each restoreValidation.warnings as warning}
                        <li>{warning}</li>
                      {/each}
                    </ul>
                  </div>
                {/if}

                {#if restoreValidation.pii_key_match === false}
                  <div class="restore-warning-box">
                    PII encryption key differs. Encrypted data may need re-encryption after restore.
                  </div>
                {/if}

                <div class="restore-options">
                <h4>Restore Options</h4>
                <label class="checkbox-option">
                  <input type="checkbox" bind:checked={restoreDbOnly} disabled={restorePhotosOnly || !restoreValidation.manifest?.contents?.database?.included} />
                  <span>Database only</span>
                </label>
                <label class="checkbox-option">
                  <input type="checkbox" bind:checked={restorePhotosOnly} disabled={restoreDbOnly || !restoreValidation.manifest?.contents?.photos?.included} />
                  <span>Photos only</span>
                </label>
                <label class="checkbox-option">
                  <input type="checkbox" bind:checked={restoreSkipPreBackup} />
                  <span>Skip pre-restore backup (not recommended)</span>
                </label>
              </div>

              {#if restoreInProgress}
                <div class="progress-container">
                  <div class="progress-bar">
                    <div class="progress-fill" style="width: {restoreProgress}%"></div>
                  </div>
                  <div class="progress-text">{restoreCurrentStep}</div>
                </div>
              {:else if restoreConfirmationPending}
                <div class="restore-confirmation">
                  <p class="warning-text">This will replace your current data!</p>
                  <p>Are you sure you want to proceed?</p>
                  <div class="restore-actions">
                    <button class="danger" on:click={startRestore}>Yes, Restore Now</button>
                    <button class="secondary" on:click={() => restoreConfirmationPending = false}>Cancel</button>
                  </div>
                </div>
              {:else}
                <div class="restore-actions">
                  <button class="primary" on:click={confirmRestore}>Restore</button>
                  <button class="secondary" on:click={cancelRestore}>Cancel</button>
                </div>
              {/if}
              {/if}
            </div>
          </div>
        {/if}
      </div>
    {:else if activeTab === 'legal'}
      <div class="legal-pages">
        <h2>Legal Pages</h2>
        <p class="legal-description">Edit the Privacy Policy and Terms of Service pages that are displayed publicly on the site.</p>

        {#if legalError}
          <div class="inline-error">{legalError}</div>
        {/if}

        {#if legalNotice}
          <div class="inline-notice success">{legalNotice}</div>
        {/if}

        <div class="legal-page-tabs">
          <button
            class="legal-tab-btn"
            class:active={legalActivePage === 'privacy_policy'}
            on:click={() => switchLegalPage('privacy_policy')}
          >
            Privacy Policy
          </button>
          <button
            class="legal-tab-btn"
            class:active={legalActivePage === 'terms_of_service'}
            on:click={() => switchLegalPage('terms_of_service')}
          >
            Terms of Service
          </button>
        </div>

        {#if legalLoading}
          <div class="loading-indicator">Loading legal pages...</div>
        {:else}
          <div class="legal-editor-section">
            <div class="legal-title-row">
              <label for="legal-title">Page Title</label>
              <input
                id="legal-title"
                type="text"
                bind:value={legalPages[legalActivePage].title}
                placeholder="Page title"
              />
            </div>

            <div class="legal-editor-container">
              <label>Content</label>
              <div id="legal-editor"></div>
            </div>

            <div class="legal-meta">
              {#if legalPages[legalActivePage].last_updated}
                <span class="last-updated">
                  Last updated: {formatLegalDate(legalPages[legalActivePage].last_updated)}
                  {#if legalPages[legalActivePage].editor_email}
                    by {legalPages[legalActivePage].editor_email}
                  {/if}
                </span>
              {:else}
                <span class="last-updated">Not yet published</span>
              {/if}
            </div>

            <div class="legal-actions">
              <button
                class="primary"
                on:click={saveLegalPage}
                disabled={legalSaving || !quillLoaded}
              >
                {legalSaving ? 'Saving...' : 'Save Changes'}
              </button>
              <a
                href={legalActivePage === 'privacy_policy' ? '/privacy' : '/terms'}
                target="_blank"
                class="secondary-link"
              >
                View Public Page
              </a>
              <button
                class="secondary"
                on:click={resetToDefault}
                disabled={legalSaving}
              >
                Reset to Default
              </button>
            </div>
          </div>
        {/if}
      </div>
    {/if}
  </div>
  {/if}
</div>

<style>
  .console-container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
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

  h1 {
    color: var(--text-primary);
    margin-bottom: 2rem;
    font-weight: 600;
  }

  h2 {
    color: var(--text-primary);
    margin-top: 2rem;
    margin-bottom: 1rem;
    font-weight: 600;
  }

  h3 {
    color: var(--text-primary);
    margin-top: 1.5rem;
    margin-bottom: 0.5rem;
    font-weight: 600;
  }

  .tabs {
    display: flex;
    gap: 0.75rem;
    border-bottom: none;
    margin-bottom: 2rem;
    flex-wrap: wrap;
    padding: 0.5rem;
    background: var(--bg-secondary);
    border-radius: 12px;
  }

  .tabs button {
    padding: 0 20px;
    height: 36px;
    background: transparent;
    border: none;
    border-radius: 18px;
    cursor: pointer;
    color: var(--text-secondary);
    transition: all 0.15s ease;
    font-weight: 500;
    font-size: 0.875rem;
  }

  .tabs button:hover {
    color: var(--text-primary);
    background: rgba(0, 122, 255, 0.08);
  }

  .tabs button.active {
    color: white;
    background: var(--accent-color);
    font-weight: 600;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .tab-content {
    padding: 1rem 0;
  }

  .overview {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  .health-status {
    padding: 1.25rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .status-badge {
    display: inline-flex;
    align-items: center;
    padding: 0 16px;
    height: 32px;
    border-radius: 16px;
    background: var(--error-color);
    color: white;
    font-weight: 600;
    font-size: 0.875rem;
  }

  .status-badge.healthy {
    background: var(--success-color);
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
  }

  .stat-card {
    padding: 1.25rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
    transition: all 0.15s ease;
  }

  .stat-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
  }

  .stat-label {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }

  .stat-value {
    color: var(--text-primary);
    font-size: 2rem;
    font-weight: bold;
  }

  .recent-activity {
    padding: 1.25rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .activity-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    color: var(--text-primary);
  }

  .info-section {
    padding: 1.25rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    color: var(--text-primary);
  }

  .api-test-section {
    padding: 1.25rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
    margin-bottom: 1.5rem;
  }

  .api-test-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .api-test-header h3 {
    margin: 0;
    color: var(--text-primary);
  }

  .test-api-btn {
    display: inline-flex;
    align-items: center;
    padding: 0 20px;
    height: 36px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 18px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.875rem;
    transition: all 0.15s ease;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .test-api-btn:hover:not(:disabled) {
    filter: brightness(1.05);
    transform: translateY(-1px);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
  }

  .test-api-btn:disabled {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    cursor: not-allowed;
    box-shadow: none;
  }

  .api-test-result {
    padding: 0.75rem 1rem;
    border-radius: 10px;
    margin-bottom: 0.5rem;
  }

  .api-test-result.success {
    background: rgba(76, 175, 80, 0.1);
    border: 1px solid var(--success-color);
    color: var(--success-color);
  }

  .api-test-result.error {
    background: rgba(211, 47, 47, 0.1);
    border: 1px solid var(--error-color);
    color: var(--error-color);
  }

  .api-test-result p {
    margin: 0.25rem 0;
  }

  .last-check {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 0.5rem;
  }

  .periodic-check-info {
    color: var(--text-secondary);
    font-size: 0.8125rem;
    font-style: italic;
  }

  .rate-limit-warning {
    color: #f59e0b;
    font-weight: 500;
    margin-top: 0.5rem;
    font-style: normal;
  }

  .filters {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  .filters input {
    height: 40px;
    padding: 0 16px;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    flex: 1;
    transition: all 0.15s ease;
  }

  .filters input:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
  }

  .filters button {
    display: inline-flex;
    align-items: center;
    padding: 0 20px;
    height: 40px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 20px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.875rem;
    transition: all 0.15s ease;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .filters button:hover {
    filter: brightness(1.05);
    transform: translateY(-1px);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1rem;
    background: var(--bg-primary);
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid var(--border-color);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  th {
    background: var(--bg-secondary);
    color: var(--text-primary);
    padding: 0.875rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
    font-weight: 600;
    font-size: 0.875rem;
  }

  td {
    padding: 0.875rem 1rem;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border-color);
  }

  tr:hover {
    background: rgba(0, 122, 255, 0.04);
  }

  .user-summary {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin: 0.5rem 0 1rem;
    color: var(--text-secondary);
    font-size: 0.95rem;
  }

  .inline-error {
    background: rgba(211, 47, 47, 0.1);
    border: 1px solid var(--error-color);
    color: var(--error-color);
    padding: 0.75rem 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
  }

  .inline-info {
    background: rgba(220, 38, 38, 0.08);
    border: 1px solid rgba(220, 38, 38, 0.35);
    color: var(--text-primary);
    padding: 0.75rem 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
    font-size: 0.95rem;
  }

  .inline-info.small {
    margin-top: 0.35rem;
    margin-bottom: 0;
    font-size: 0.9rem;
  }

  .alert-list {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0 0;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .alert-header {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .alert-subtext {
    color: var(--text-secondary);
    font-size: 0.9rem;
  }

  .alert-grid {
    display: grid;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }

  .alert-type {
    font-weight: 600;
    margin-right: 0.5rem;
    color: var(--accent-color);
  }

  .alert-meta {
    color: var(--text-secondary);
    font-size: 0.9rem;
    margin-right: 0.5rem;
  }

  .alert-details {
    color: var(--text-secondary);
    font-size: 0.9rem;
    word-break: break-word;
  }

  .alert-row {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .alert-row-main {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .alert-actions {
    margin-top: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .alert-action-list ul {
    margin: 0.25rem 0 0;
    padding-left: 1.2rem;
    color: var(--text-secondary);
  }

  .alert-buttons {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .purge-card {
    margin-top: 1rem;
    padding: 0.75rem 1rem;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    align-items: center;
  }

  .purge-card input[type='number'] {
    width: 90px;
    padding: 0.4rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
  }

  .user-email {
    font-weight: 600;
    color: var(--text-primary);
  }

  .pill {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    border-radius: 999px;
    font-size: 0.85rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    text-transform: capitalize;
  }

  .pill-admin {
    background: rgba(16, 185, 129, 0.15);
    color: #0f9d58;
    border-color: rgba(16, 185, 129, 0.4);
  }

  .pill-artist,
  .pill-artist-guest {
    background: rgba(59, 130, 246, 0.12);
    color: #2563eb;
    border-color: rgba(59, 130, 246, 0.35);
  }

  .pill-guest,
  .pill-visitor {
    background: var(--bg-secondary);
    color: var(--text-secondary);
  }

  .pill-warning {
    background: rgba(245, 158, 11, 0.16);
    color: #b45309;
    border-color: rgba(245, 158, 11, 0.4);
  }

  .cleanup-card {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
  }

  .cleanup-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
  }

  .cleanup-row input[type='number'] {
    width: 90px;
    padding: 0.4rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
  }

  .pill-muted {
    background: rgba(107, 114, 128, 0.15);
    color: var(--text-secondary);
    border-color: rgba(107, 114, 128, 0.4);
  }

  .user-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .user-actions button {
    padding: 0.35rem 0.75rem;
    border-radius: 6px;
    border: 1px solid var(--border-color);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
  }

  .user-actions button.secondary {
    background: var(--bg-tertiary);
  }

  .user-actions button.danger {
    background: #b91c1c;
    color: white;
    border-color: #991b1b;
  }

  .user-actions button:disabled {
    cursor: not-allowed;
    opacity: 0.6;
  }

  .pagination {
    display: flex;
    gap: 1rem;
    align-items: center;
    justify-content: center;
    margin-top: 1.5rem;
  }

  .pagination button {
    display: inline-flex;
    align-items: center;
    padding: 0 20px;
    height: 36px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 18px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.875rem;
    transition: all 0.15s ease;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .pagination button:hover:not(:disabled) {
    filter: brightness(1.05);
    transform: translateY(-1px);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
  }

  .pagination button:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    cursor: not-allowed;
    box-shadow: none;
    transform: none;
  }

  .pagination span {
    color: var(--text-primary);
    font-weight: 500;
  }

  .error-message {
    padding: 1rem 1.25rem;
    background: rgba(211, 47, 47, 0.08);
    color: var(--error-color);
    border: 1px solid rgba(211, 47, 47, 0.3);
    border-radius: 10px;
    margin-bottom: 2rem;
    font-weight: 500;
  }

  .loading {
    padding: 2rem;
    text-align: center;
    color: var(--text-secondary);
  }

  /* CLI Styles - Traditional Terminal Look */
  .cli {
    display: flex;
    flex-direction: column;
    height: calc(100vh - 200px);
    min-height: 600px;
    background: #1e1e1e;
    border: 1px solid #333;
    border-radius: 0;
    font-family: 'Courier New', 'Monaco', 'Menlo', 'Consolas', monospace;
    overflow: hidden;
  }

  .cli-controls {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 1rem;
    background: #2d2d2d;
    border-bottom: 1px solid #444;
    font-size: 0.75rem;
  }

  .write-mode-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .write-mode-toggle label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    color: #00ff00;
    font-family: inherit;
  }

  .write-mode-toggle input[type="checkbox"] {
    cursor: pointer;
  }

  .write-mode-toggle span.active {
    color: #ff6b6b;
    font-weight: bold;
  }

  .write-mode-warning {
    color: #ff6b6b;
    font-size: 0.75rem;
    font-weight: bold;
    font-family: inherit;
  }

  .clear-btn {
    padding: 0.25rem 0.75rem;
    background: #333;
    color: #00ff00;
    border: 1px solid #555;
    border-radius: 0;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.75rem;
  }

  .clear-btn:hover {
    background: #444;
    border-color: #00ff00;
  }

  .cli-input-area {
    display: flex;
    gap: 0;
    align-items: stretch;
    background: #1e1e1e;
    border-top: 1px solid #333;
    padding: 0.5rem;
  }

  .input-wrapper {
    position: relative;
    flex: 1;
    display: flex;
    align-items: center;
    background: #1e1e1e;
  }

  .prompt {
    color: #00ff00;
    margin-right: 0.5rem;
    font-weight: bold;
    font-family: inherit;
    font-size: 1rem;
    user-select: none;
  }

  .input-wrapper input {
    flex: 1;
    padding: 0.5rem;
    background: #1e1e1e;
    border: none;
    border-radius: 0;
    color: #00ff00;
    font-family: inherit;
    font-size: 1rem;
    outline: none;
  }

  .input-wrapper input.write-mode-active {
    color: #ff6b6b;
  }

  .input-wrapper input::placeholder {
    color: #666;
  }

  .autocomplete-dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: #2d2d2d;
    border: 1px solid #444;
    border-top: none;
    border-radius: 0;
    margin-top: 0;
    max-height: 300px;
    overflow-y: auto;
    z-index: 100;
    box-shadow: none;
    font-family: inherit;
  }

  .autocomplete-item {
    padding: 0.5rem 0.75rem;
    cursor: pointer;
    border-bottom: 1px solid #333;
    transition: background 0.1s;
    font-family: inherit;
  }

  .autocomplete-item:hover {
    background: #3d3d3d;
  }

  .autocomplete-item:last-child {
    border-bottom: none;
  }

  .suggestion-desc {
    color: #888;
    font-size: 0.75rem;
    font-family: inherit;
  }


  .confirmation-warning {
    padding: 0.75rem 1rem;
    border-radius: 0;
    border-left: 3px solid #ff6b6b;
    border-right: none;
    border-top: none;
    border-bottom: none;
    background: #2d1e1e;
    font-family: inherit;
  }

  .confirmation-warning.step1 {
    border-left-color: #ffaa00;
    background: #2d251e;
  }

  .confirmation-warning.step2 {
    border-left-color: #ff6b6b;
    background: #2d1e1e;
  }

  .confirmation-warning p {
    margin: 0.25rem 0;
    color: #ff6b6b;
    font-family: inherit;
    font-size: 0.875rem;
  }

  .confirmation-warning strong {
    color: #ff6b6b;
    font-family: inherit;
  }

  .cli-output {
    flex: 1;
    overflow-y: auto;
    background: #1e1e1e;
    border: none;
    border-radius: 0;
    padding: 1rem;
    font-family: inherit;
    font-size: 1rem;
    line-height: 1.6;
    color: #00ff00;
  }

  .cli-output::-webkit-scrollbar {
    width: 8px;
  }

  .cli-output::-webkit-scrollbar-track {
    background: #1e1e1e;
  }

  .cli-output::-webkit-scrollbar-thumb {
    background: #444;
  }

  .cli-output::-webkit-scrollbar-thumb:hover {
    background: #555;
  }

  .output-line {
    margin-bottom: 0.25rem;
    word-wrap: break-word;
    font-family: inherit;
  }

  .output-line.command {
    color: #00ff00;
  }

  .output-line.success {
    color: #00ff00;
  }

  .output-line.error {
    color: #ff6b6b;
  }

  .output-line.warning {
    color: #ffaa00;
  }

  .output-line.data {
    color: #e0e0e0;
    white-space: pre-wrap;
  }

  .output-timestamp {
    color: #666;
    margin-right: 0.5rem;
    font-family: inherit;
  }

  .output-placeholder {
    color: #666;
    text-align: left;
    padding: 1rem;
    font-family: inherit;
  }

  .output-placeholder p {
    margin: 0.5rem 0;
    font-family: inherit;
  }

  .output-line pre {
    margin: 0;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-family: inherit;
    background: transparent;
    color: inherit;
  }

  .password-reset-tab {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .reset-header {
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1rem;
    align-items: flex-end;
    margin-bottom: 0.5rem;
  }

  .reset-subtitle {
    margin: 0.25rem 0 0;
    font-size: 0.875rem;
    color: var(--text-secondary);
    line-height: 1.5;
  }

  .reset-controls {
    display: flex;
    gap: 0.75rem;
    align-items: flex-end;
  }

  .reset-controls label {
    font-size: 0.875rem;
    color: var(--text-primary);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    font-weight: 500;
  }

  .reset-controls select {
    padding: 0.625rem 0.875rem;
    border-radius: 4px;
    border: 1px solid var(--border-color);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.875rem;
    font-family: inherit;
    cursor: pointer;
    transition: all 0.2s;
    min-width: 140px;
  }

  .reset-controls select:hover:not(:disabled) {
    border-color: var(--accent-color);
    box-shadow: 0 0 0 1px rgba(66, 133, 244, 0.1);
  }

  .reset-controls select:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 2px rgba(66, 133, 244, 0.1);
  }

  .reset-controls select:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .reset-controls button.secondary {
    padding: 0.625rem 1rem;
    border-radius: 4px;
    border: 1px solid var(--border-color);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-size: 0.875rem;
    font-weight: 500;
    font-family: inherit;
    cursor: pointer;
    transition: all 0.2s;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .reset-controls button.secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
    color: var(--accent-color);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
  }

  .reset-controls button.secondary:active:not(:disabled) {
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .reset-controls button.secondary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
  }

  .reset-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 1.25rem;
  }

  .reset-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    transition: all 0.2s;
  }

  .reset-card:hover {
    border-color: var(--accent-color);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  }

  .reset-card-header {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    align-items: flex-start;
  }

  .reset-email {
    font-weight: 600;
    font-size: 1rem;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
  }

  .reset-meta {
    font-size: 0.8125rem;
    color: var(--text-secondary);
    line-height: 1.5;
    margin-top: 0.25rem;
  }

  .reset-meta.hint {
    font-style: italic;
    color: var(--text-tertiary);
  }

  .reset-message {
    background: var(--bg-tertiary);
    border-radius: 6px;
    padding: 0.75rem;
    font-size: 0.875rem;
    color: var(--text-primary);
    line-height: 1.5;
    border-left: 3px solid var(--border-color);
  }

  .reset-message.admin {
    border-left-color: var(--accent-color);
    background: rgba(66, 133, 244, 0.08);
  }

  .reset-note-label {
    font-size: 0.875rem;
    color: var(--text-primary);
    font-weight: 500;
    margin-bottom: 0.25rem;
  }

  .reset-card textarea {
    width: 100%;
    border-radius: 4px;
    border: 1px solid var(--border-color);
    background: var(--bg-primary);
    color: var(--text-primary);
    padding: 0.75rem;
    resize: vertical;
    font-family: inherit;
    font-size: 0.875rem;
    transition: all 0.2s;
    box-sizing: border-box;
  }

  .reset-card textarea:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 2px rgba(66, 133, 244, 0.1);
  }

  .reset-card textarea:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    background: var(--bg-tertiary);
  }

  .reset-card-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.25rem;
  }

  .reset-card-actions button {
    padding: 0.625rem 1rem;
    border-radius: 4px;
    border: 1px solid var(--border-color);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    font-family: inherit;
    transition: all 0.2s;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .reset-card-actions button.secondary {
    background: var(--bg-tertiary);
    border-color: var(--border-color);
    color: var(--text-primary);
  }

  .reset-card-actions button.secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
    color: var(--accent-color);
  }

  .reset-card-actions button:hover:not(:disabled) {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
  }

  .reset-card-actions button.primary {
    background: var(--accent-color);
    border-color: var(--accent-color);
    color: white;
  }

  .reset-card-actions button.primary:hover:not(:disabled) {
    background: var(--accent-hover);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
  }

  .reset-card-actions button.primary:active:not(:disabled) {
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .reset-card-actions button.primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    border-color: var(--border-color);
  }

  .reset-card-actions button.danger {
    border-color: var(--error-color);
    color: var(--error-color);
    background: transparent;
  }

  .reset-card-actions button.danger:hover:not(:disabled) {
    background: rgba(211, 47, 47, 0.1);
    border-color: var(--error-color);
  }

  .reset-card-actions button.danger:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .code-banner {
    padding: 0.75rem;
    background: rgba(66, 133, 244, 0.12);
    border: 1px solid rgba(66, 133, 244, 0.35);
    border-radius: 6px;
    font-size: 0.875rem;
    color: var(--text-primary);
    line-height: 1.5;
  }

  .code-banner code {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.9375rem;
    font-weight: 600;
    color: var(--accent-color);
    background: rgba(66, 133, 244, 0.1);
    padding: 0.125rem 0.375rem;
    border-radius: 3px;
  }

  .pill-pending {
    background: rgba(245, 158, 11, 0.16);
    color: #b45309;
    border-color: rgba(245, 158, 11, 0.4);
  }

  .pill-approved {
    background: rgba(66, 133, 244, 0.12);
    color: #1a73e8;
    border-color: rgba(66, 133, 244, 0.35);
  }

  .pill-denied {
    background: rgba(211, 47, 47, 0.12);
    color: #c5221f;
    border-color: rgba(211, 47, 47, 0.35);
  }

  .pill-completed {
    background: rgba(52, 168, 83, 0.12);
    color: #137333;
    border-color: rgba(52, 168, 83, 0.35);
  }

  .pill-expired {
    background: rgba(255, 152, 0, 0.16);
    color: #b45309;
    border-color: rgba(255, 152, 0, 0.4);
  }

  /* Artist Assignments Section - Google-like Design */
  .artist-assignments {
    margin-top: 2rem;
    padding: 1.5rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border-color);
  }

  .artist-assignments-header {
    margin-bottom: 1.5rem;
  }

  .artist-assignments-header h3 {
    margin: 0 0 0.5rem 0;
    font-size: 1.25rem;
    font-weight: 500;
    color: var(--text-primary);
    letter-spacing: -0.25px;
  }

  .artist-assignments-description {
    margin: 0;
    font-size: 0.875rem;
    color: var(--text-secondary);
    line-height: 1.5;
  }

  .loading-state {
    padding: 1.5rem;
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .assign-form {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .form-field label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
  }

  .select-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .form-select {
    width: 100%;
    padding: 0.875rem 1rem;
    padding-right: 2.5rem;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 0.9375rem;
    font-family: inherit;
    cursor: pointer;
    transition: all 0.2s ease;
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23999' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 0.75rem center;
    background-size: 12px;
  }

  :global(:root[data-theme='light'] .form-select) {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23666' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
  }

  .form-select:hover:not(:disabled) {
    border-color: var(--accent-color);
    box-shadow: 0 0 0 1px rgba(66, 133, 244, 0.1);
  }

  .form-select:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 2px rgba(66, 133, 244, 0.1);
  }

  .form-select:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    background-color: var(--bg-tertiary);
  }

  .form-select option {
    background: var(--bg-primary);
    color: var(--text-primary);
    padding: 0.5rem;
  }

  .assign-actions {
    display: flex;
    gap: 0.75rem;
    margin-top: 0.5rem;
    flex-wrap: wrap;
  }

  .assign-button {
    padding: 0.75rem 1.5rem;
    border-radius: 4px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    border: none;
    font-family: inherit;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .assign-button.primary {
    background: var(--accent-color);
    color: white;
  }

  .assign-button.primary:hover:not(:disabled) {
    background: var(--accent-hover);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
  }

  .assign-button.primary:active:not(:disabled) {
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .assign-button.secondary {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .assign-button.secondary:hover:not(:disabled) {
    background: var(--bg-secondary);
    border-color: var(--accent-color);
    color: var(--accent-color);
  }

  .assign-button.secondary:active:not(:disabled) {
    background: var(--bg-tertiary);
  }

  .assign-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    box-shadow: none;
  }

  .assign-button.primary:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
  }

  .assign-button.secondary:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    border-color: var(--border-color);
  }

  @media (max-width: 600px) {
    .artist-assignments {
      padding: 1rem;
    }

    .assign-actions {
      flex-direction: column;
    }

    .assign-button {
      width: 100%;
    }
  }

  /* Backup Section Styles */
  .backup-section {
    padding: 1rem 0;
  }

  .backup-create {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }

  .backup-options {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .backup-option {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    padding: 0.5rem 1rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    border: 1px solid var(--border-color);
    transition: all 0.2s;
  }

  .backup-option:hover {
    border-color: var(--accent-color);
  }

  .backup-option input[type="radio"] {
    accent-color: var(--accent-color);
  }

  .backup-extra-options {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }

  .checkbox-option {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
  }

  .checkbox-option input[type="checkbox"] {
    accent-color: var(--accent-color);
  }

  .checkbox-option input:disabled + span {
    opacity: 0.5;
  }

  .backup-btn {
    padding: 0.75rem 2rem;
    font-size: 1rem;
  }

  .progress-container {
    margin-top: 1rem;
  }

  .progress-bar {
    height: 8px;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: var(--accent-color);
    transition: width 0.3s ease;
  }

  .progress-text {
    margin-top: 0.5rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .backup-list-section {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 1.5rem;
  }

  .backup-list-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .backup-list-header h3 {
    margin: 0;
  }

  .no-backups {
    padding: 2rem;
    text-align: center;
    color: var(--text-secondary);
    font-style: italic;
  }

  .backup-table {
    width: 100%;
    border-collapse: collapse;
  }

  .backup-table th,
  .backup-table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
  }

  .backup-table th {
    background: var(--bg-secondary);
    font-weight: 600;
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .backup-table td.filename {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.8125rem;
    word-break: break-all;
  }

  .backup-type-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .backup-type-badge.full {
    background: rgba(52, 168, 83, 0.15);
    color: #34a853;
  }

  .backup-type-badge.db {
    background: rgba(66, 133, 244, 0.15);
    color: #4285f4;
  }

  .backup-type-badge.photos {
    background: rgba(251, 188, 4, 0.15);
    color: #f9ab00;
  }

  .backup-encrypted-badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
    background: rgba(156, 39, 176, 0.15);
    color: #9c27b0;
    margin-left: 0.375rem;
  }

  .backup-encryption-options {
    margin-top: 1rem;
    padding: 1rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border-color);
  }

  .encryption-method {
    margin-top: 0.75rem;
    padding-left: 1.5rem;
  }

  .passphrase-inputs {
    margin-top: 0.75rem;
  }

  .passphrase-inputs .input-group {
    margin-bottom: 0.75rem;
  }

  .passphrase-inputs .input-group label {
    display: block;
    font-size: 0.875rem;
    margin-bottom: 0.25rem;
    color: var(--text-secondary);
  }

  .passphrase-inputs .input-group input {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.875rem;
  }

  .passphrase-inputs .input-group input:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .passphrase-hint {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 0.25rem;
  }

  .restore-encryption-section {
    margin: 1rem 0;
    padding: 1rem;
    background: rgba(156, 39, 176, 0.1);
    border-radius: 8px;
    border: 1px solid rgba(156, 39, 176, 0.3);
  }

  .restore-encryption-section h4 {
    margin: 0 0 0.5rem 0;
    color: #9c27b0;
  }

  .encryption-info {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin-bottom: 0.75rem;
  }

  .restore-encryption-section .input-group {
    margin-top: 0.75rem;
  }

  .restore-encryption-section .input-group label {
    display: block;
    font-size: 0.875rem;
    margin-bottom: 0.25rem;
    color: var(--text-secondary);
  }

  .restore-encryption-section .input-group input {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.875rem;
  }

  .restore-encryption-section .input-group input:focus {
    outline: none;
    border-color: #9c27b0;
  }

  .backup-table td.actions {
    white-space: nowrap;
  }

  .action-btn {
    padding: 0.375rem 0.75rem;
    border-radius: 4px;
    border: 1px solid var(--border-color);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
    font-size: 0.75rem;
    margin-right: 0.25rem;
    transition: all 0.2s;
  }

  .action-btn:hover:not(:disabled) {
    border-color: var(--accent-color);
  }

  .action-btn.download:hover:not(:disabled) {
    color: var(--accent-color);
  }

  .action-btn.restore:hover:not(:disabled) {
    color: var(--success-color);
    border-color: var(--success-color);
  }

  .action-btn.delete:hover:not(:disabled) {
    color: var(--error-color);
    border-color: var(--error-color);
  }

  .action-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .restore-modal-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .restore-modal {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 2rem;
    max-width: 500px;
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
  }

  .restore-modal h3 {
    margin-top: 0;
    margin-bottom: 0.5rem;
  }

  .restore-filename {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin-bottom: 1rem;
    word-break: break-all;
  }

  .restore-info {
    background: var(--bg-secondary);
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .restore-info div {
    margin-bottom: 0.25rem;
  }

  .restore-warnings {
    background: rgba(251, 188, 4, 0.1);
    border: 1px solid rgba(251, 188, 4, 0.3);
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .restore-warnings ul {
    margin: 0.5rem 0 0 1.5rem;
    padding: 0;
  }

  .restore-warning-box {
    background: rgba(211, 47, 47, 0.1);
    border: 1px solid rgba(211, 47, 47, 0.3);
    color: var(--error-color);
    padding: 0.75rem 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }

  .restore-options {
    margin-bottom: 1.5rem;
  }

  .restore-options h4 {
    margin-bottom: 0.75rem;
  }

  .restore-confirmation {
    background: rgba(211, 47, 47, 0.1);
    border: 1px solid rgba(211, 47, 47, 0.3);
    padding: 1rem;
    border-radius: 4px;
    text-align: center;
  }

  .restore-confirmation .warning-text {
    color: var(--error-color);
    font-weight: 600;
    font-size: 1.125rem;
    margin-bottom: 0.5rem;
  }

  .restore-actions {
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
    margin-top: 1rem;
  }

  .restore-actions button {
    padding: 0.625rem 1.25rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: all 0.2s;
  }

  .restore-actions button.primary {
    background: var(--accent-color);
    border: 1px solid var(--accent-color);
    color: white;
  }

  .restore-actions button.primary:hover {
    background: var(--accent-hover);
  }

  .restore-actions button.secondary {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
  }

  .restore-actions button.secondary:hover {
    border-color: var(--accent-color);
  }

  .restore-actions button.danger {
    background: var(--error-color);
    border: 1px solid var(--error-color);
    color: white;
  }

  .restore-actions button.danger:hover {
    background: #b71c1c;
  }

  @media (max-width: 768px) {
    .backup-options {
      flex-direction: column;
    }

    .backup-table {
      font-size: 0.875rem;
    }

    .backup-table th,
    .backup-table td {
      padding: 0.5rem;
    }

    .action-btn {
      padding: 0.25rem 0.5rem;
      font-size: 0.6875rem;
    }
  }

  /* Legal Pages Styles */
  .legal-pages {
    max-width: 900px;
  }

  .legal-description {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
    font-size: 0.9375rem;
  }

  .legal-page-tabs {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
  }

  .legal-tab-btn {
    padding: 0.5rem 1.25rem;
    border: 1px solid var(--border-color);
    background: var(--bg-primary);
    color: var(--text-secondary);
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: all 0.15s ease;
  }

  .legal-tab-btn:hover {
    background: rgba(0, 122, 255, 0.08);
    border-color: var(--accent-color);
    color: var(--accent-color);
  }

  .legal-tab-btn.active {
    background: var(--accent-color);
    color: white;
    border-color: var(--accent-color);
  }

  .legal-editor-section {
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05);
  }

  .legal-title-row {
    margin-bottom: 1.25rem;
  }

  .legal-title-row label,
  .legal-editor-container label {
    display: block;
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
  }

  .legal-title-row input {
    width: 100%;
    height: 44px;
    padding: 0 16px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    font-size: 1rem;
    background: var(--bg-primary);
    color: var(--text-primary);
    box-sizing: border-box;
    transition: all 0.15s ease;
  }

  .legal-title-row input:focus {
    outline: none;
    border-color: var(--accent-color);
    box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
  }

  .legal-editor-container {
    margin-bottom: 1rem;
  }

  #legal-editor {
    min-height: 400px;
    background: var(--bg-primary);
    border: 1px solid var(--border-color);
    border-radius: 0 0 8px 8px;
  }

  /* Quill editor theme overrides */
  :global(.ql-toolbar.ql-snow) {
    border: 1px solid var(--border-color);
    border-radius: 8px 8px 0 0;
    background: var(--bg-secondary);
  }

  :global(.ql-container.ql-snow) {
    border: 1px solid var(--border-color);
    border-top: none;
    border-radius: 0 0 8px 8px;
    font-size: 1rem;
    font-family: inherit;
  }

  :global(.ql-editor) {
    min-height: 400px;
    color: var(--text-primary);
  }

  :global(.ql-editor.ql-blank::before) {
    color: var(--text-secondary);
    font-style: normal;
  }

  :global(.ql-snow .ql-stroke) {
    stroke: var(--text-secondary);
  }

  :global(.ql-snow .ql-fill) {
    fill: var(--text-secondary);
  }

  :global(.ql-snow .ql-picker-label) {
    color: var(--text-secondary);
  }

  :global(.ql-snow .ql-picker-options) {
    background: var(--bg-primary);
    border-color: var(--border-color);
  }

  :global(.ql-toolbar.ql-snow .ql-picker-label:hover),
  :global(.ql-toolbar.ql-snow button:hover) {
    color: var(--accent-color);
  }

  :global(.ql-toolbar.ql-snow button:hover .ql-stroke) {
    stroke: var(--accent-color);
  }

  .legal-meta {
    margin-bottom: 1.25rem;
    padding-top: 0.75rem;
  }

  .legal-meta .last-updated {
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .legal-actions {
    display: flex;
    gap: 1rem;
    align-items: center;
  }

  .legal-actions button.primary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 24px;
    height: 44px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 22px;
    font-weight: 600;
    font-size: 0.9375rem;
    cursor: pointer;
    transition: all 0.15s ease;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
  }

  .legal-actions button.primary:hover:not(:disabled) {
    filter: brightness(1.05);
    transform: translateY(-1px);
    box-shadow: 0 2px 8px rgba(0, 122, 255, 0.3);
  }

  .legal-actions button.primary:disabled {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    cursor: not-allowed;
    box-shadow: none;
  }

  .legal-actions button.secondary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 20px;
    height: 40px;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
    border-radius: 20px;
    font-weight: 500;
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .legal-actions button.secondary:hover:not(:disabled) {
    border-color: var(--accent-color);
    color: var(--accent-color);
  }

  .legal-actions button.secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .secondary-link {
    color: var(--accent-color);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.9375rem;
    transition: all 0.15s ease;
  }

  .secondary-link:hover {
    text-decoration: underline;
  }

  .loading-indicator {
    padding: 2rem;
    text-align: center;
    color: var(--text-secondary);
  }

  .inline-notice.success {
    background: rgba(76, 175, 80, 0.1);
    border: 1px solid var(--success-color);
    color: var(--success-color);
    padding: 0.75rem 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
  }
</style>
