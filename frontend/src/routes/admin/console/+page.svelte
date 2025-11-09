<script>
  import { PUBLIC_API_BASE_URL } from '$env/static/public';
  import { onMount, afterUpdate, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { auth } from '$lib/stores/auth';

  export let data;

  let stats = null;
  let health = null;
  let loadError = null;
  let isLoading = true;

  // Load data client-side with credentials
  onMount(async () => {
    await auth.init();
    
    // Wait a tick for auth state to update
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Check if user is admin
    if (!$auth.isAuthenticated || $auth.user?.role !== 'admin') {
      goto('/');
      return;
    }

    // Load stats and health data
    try {
      const [statsRes, healthRes] = await Promise.all([
        fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/stats`, {
          credentials: 'include',
          headers: {
            accept: 'application/json'
          }
        }),
        fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/health`, {
          credentials: 'include',
          headers: {
            accept: 'application/json'
          }
        })
      ]);

      if (statsRes.status === 403 || healthRes.status === 403) {
        loadError = 'Access denied: Admin role required';
        goto('/');
        return;
      }
      if (statsRes.status === 401 || healthRes.status === 401) {
        loadError = 'Authentication required';
        goto('/login');
        return;
      }

      if (statsRes.ok) {
        stats = await statsRes.json();
      } else {
        loadError = `Failed to load stats: HTTP ${statsRes.status}`;
      }

      if (healthRes.ok) {
        health = await healthRes.json();
      } else if (!loadError) {
        loadError = `Failed to load health: HTTP ${healthRes.status}`;
      }

      if (!health) {
        health = { status: 'unknown', service: 'canvas-clay-backend' };
      }
    } catch (err) {
      console.error('Failed to load admin console data:', err);
      loadError = err instanceof Error ? err.message : 'Failed to load admin console data';
    } finally {
      isLoading = false;
    }
  });

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

  let failedLogins = [];
  let failedLoginsPagination = null;
  let failedLoginsPage = 1;

  let users = [];
  let databaseInfo = null;

  // API health check state
  let apiTestResult = null;
  let apiTestLoading = false;
  let lastApiCheck = null;
  let apiCheckInterval = null;
  let currentTime = new Date(); // For reactive time display

  // CLI state
  let writeMode = false;
  let commandInput = '';
  let commandHistory = [];
  let historyIndex = -1;
  let cliOutput = [];
  let cliHelp = null;
  let autocompleteSuggestions = [];
  let showAutocomplete = false;
  let pendingDeleteConfirmation = null;
  let confirmationStep = 0; // 0 = none, 1 = first, 2 = second
  let cliOutputElement;
  let commandInputElement;

  // Auto-scroll output to bottom whenever cliOutput changes
  afterUpdate(() => {
    if (cliOutputElement && cliOutput.length > 0) {
      cliOutputElement.scrollTop = cliOutputElement.scrollHeight;
    }
  });

  // Load command history from localStorage
  onMount(async () => {
    await auth.init();
    
    // Wait a tick for auth state to update
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Check if user is admin
    if (!$auth.isAuthenticated || $auth.user?.role !== 'admin') {
      goto('/');
      return;
    }

    // Load stats and health data
    try {
      const [statsRes, healthRes] = await Promise.all([
        fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/stats`, {
          credentials: 'include',
          headers: {
            accept: 'application/json'
          }
        }),
        fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/health`, {
          credentials: 'include',
          headers: {
            accept: 'application/json'
          }
        })
      ]);

      if (statsRes.status === 403 || healthRes.status === 403) {
        loadError = 'Access denied: Admin role required';
        goto('/');
        return;
      }
      if (statsRes.status === 401 || healthRes.status === 401) {
        loadError = 'Authentication required';
        goto('/login');
        return;
      }

      if (statsRes.ok) {
        stats = await statsRes.json();
      } else {
        loadError = `Failed to load stats: HTTP ${statsRes.status}`;
      }

      if (healthRes.ok) {
        health = await healthRes.json();
      } else if (!loadError) {
        loadError = `Failed to load health: HTTP ${healthRes.status}`;
      }

      if (!health) {
        health = { status: 'unknown', service: 'canvas-clay-backend' };
      }

      // Start periodic API check if health tab is active
      if (activeTab === 'health') {
        startPeriodicApiCheck();
      }

      // Load CLI help
      await loadCLIHelp();

      // Load command history
      const storedHistory = localStorage.getItem('admin_cli_history');
      if (storedHistory) {
        try {
          commandHistory = JSON.parse(storedHistory);
        } catch {
          commandHistory = [];
        }
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
      return new Date(dateString).toLocaleString();
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

  const loadUsers = async () => {
    loading.users = true;
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/api/admin/console/users`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });

      if (response.ok) {
        const result = await response.json();
        users = result.users || [];
      }
    } catch (err) {
      console.error('Failed to load users:', err);
    } finally {
      loading.users = false;
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

  const handleTabChange = (tab) => {
    activeTab = tab;
    
    // Stop periodic checks when leaving health tab
    if (tab !== 'health') {
      stopPeriodicApiCheck();
    }
    
    if (tab === 'security' && auditLogs.length === 0) {
      loadAuditLogs();
      loadFailedLogins();
    } else if (tab === 'users' && users.length === 0) {
      loadUsers();
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
    } else if (tab === 'health') {
      // Start periodic API health checks when health tab is opened
      startPeriodicApiCheck();
    }
  };

  const testApiConnection = async () => {
    apiTestLoading = true;
    apiTestResult = null;
    try {
      const response = await fetch(`${PUBLIC_API_BASE_URL}/`, {
        credentials: 'include',
        headers: { accept: 'application/json' }
      });
      
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
      } else {
        apiTestResult = {
          success: false,
          message: `Unexpected response: ${data.message || 'Unknown'}`
        };
      }
    } catch (err) {
      const checkTime = new Date();
      lastApiCheck = checkTime;
      // Update currentTime immediately to prevent negative time differences
      currentTime = checkTime;
      apiTestResult = {
        success: false,
        message: `Connection failed: ${err.message}`
      };
    } finally {
      apiTestLoading = false;
    }
  };

  const startPeriodicApiCheck = () => {
    // Clear existing interval if any
    if (apiCheckInterval) {
      clearInterval(apiCheckInterval);
    }
    
    // Run initial check
    testApiConnection();
    
    // Set up periodic checks every 30 seconds
    apiCheckInterval = setInterval(() => {
      testApiConnection();
    }, 30000);
  };

  const stopPeriodicApiCheck = () => {
    if (apiCheckInterval) {
      clearInterval(apiCheckInterval);
      apiCheckInterval = null;
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

    // Add command to output
    addCLIOutput(`> ${command}`, 'command');

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
      if (!$auth.csrfToken) {
        await auth.init();
      }
      
      const headers = {
        'Content-Type': 'application/json',
        accept: 'application/json'
      };
      
      // Add CSRF token if available
      if ($auth.csrfToken) {
        headers['X-CSRFToken'] = $auth.csrfToken;
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
      
      // Force scroll to bottom after all output is added
      setTimeout(() => {
        if (cliOutputElement) {
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

  const addCLIOutput = (text, type = 'info') => {
    cliOutput = [...cliOutput, {
      text,
      type,
      timestamp: new Date().toLocaleTimeString()
    }];
    // Keep last 1000 lines
    if (cliOutput.length > 1000) {
      cliOutput = cliOutput.slice(-1000);
    }
    // Auto-scroll to bottom after output is added (multiple attempts to ensure it works)
    setTimeout(() => {
      if (cliOutputElement) {
        cliOutputElement.scrollTop = cliOutputElement.scrollHeight;
      }
    }, 0);
    setTimeout(() => {
      if (cliOutputElement) {
        cliOutputElement.scrollTop = cliOutputElement.scrollHeight;
      }
    }, 10);
    setTimeout(() => {
      if (cliOutputElement) {
        cliOutputElement.scrollTop = cliOutputElement.scrollHeight;
      }
    }, 50);
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
  };

  const toggleWriteMode = () => {
    if (!writeMode) {
      if (!confirm('WARNING: Enabling write mode allows you to modify the database. Are you sure?')) {
        return;
      }
    }
    writeMode = !writeMode;
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
  
  $: if (activeTab === 'health' && lastApiCheck) {
    // Clear existing interval
    if (timeUpdateInterval) {
      clearInterval(timeUpdateInterval);
    }
    // Start new interval to update time display
    timeUpdateInterval = setInterval(() => {
      currentTime = new Date();
    }, 1000);
  } else {
    // Clear interval when not on health tab or no lastApiCheck
    if (timeUpdateInterval) {
      clearInterval(timeUpdateInterval);
      timeUpdateInterval = null;
    }
  }

  // Cleanup intervals on component destroy
  onDestroy(() => {
    stopPeriodicApiCheck();
    if (timeUpdateInterval) {
      clearInterval(timeUpdateInterval);
    }
  });
</script>

<div class="console-container">
  <h1>Admin Console</h1>

  {#if isLoading}
    <div class="loading">Loading console data...</div>
  {:else if loadError}
    <div class="error-message">
      {loadError}
      {#if loadError === 'Access denied: Admin role required' || loadError === 'Authentication required'}
        <div style="margin-top: 1rem;">
          <a href="/login">Go to Login</a> | <a href="/">Go to Home</a>
        </div>
      {/if}
    </div>
  {:else if !stats}
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
      class:active={activeTab === 'health'}
      on:click={() => handleTabChange('health')}
    >
      Health
    </button>
    <button
      class:active={activeTab === 'security'}
      on:click={() => handleTabChange('security')}
    >
      Security
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
  </div>

  <div class="tab-content">
    {#if activeTab === 'overview'}
      <div class="overview">
        <div class="health-status">
          <h2>System Health</h2>
          <div class="status-badge" class:healthy={health?.status === 'healthy'}>
            {health?.status || 'unknown'}
          </div>
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
        </div>

        <div class="recent-activity">
          <h2>Recent Activity (Last 24h)</h2>
          <div class="activity-list">
            <div>New Artworks: {stats?.recent_activity?.artworks_last_24h || 0}</div>
            <div>New Photos: {stats?.recent_activity?.photos_last_24h || 0}</div>
            <div>New Users: {stats?.recent_activity?.users_last_24h || 0}</div>
            <div>Failed Logins: {stats?.recent_activity?.failed_logins_last_24h || 0}</div>
          </div>
        </div>
      </div>
    {:else if activeTab === 'health'}
      <div class="health">
        <h2>System Health</h2>
        
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
                <p><strong>Status:</strong> {apiTestResult.status}</p>
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
            <p>Automatic health checks run every 30 seconds when this tab is active.</p>
          </div>
        </div>
        
        <div class="info-section">
          <div><strong>Status:</strong> {health?.status || 'unknown'}</div>
          <div><strong>Service:</strong> {health?.service || 'unknown'}</div>
          <div><strong>Database Status:</strong> {health?.database?.status || 'unknown'}</div>
          <div><strong>Database Engine:</strong> {health?.database?.engine || 'unknown'}</div>
          <div><strong>Environment:</strong> {health?.environment || 'unknown'}</div>
        </div>
      </div>
    {:else if activeTab === 'security'}
      <div class="security">
        <h2>Audit Logs</h2>
        <div class="filters">
          <input
            type="text"
            bind:value={auditLogEventType}
            placeholder="Filter by event type..."
            on:keydown={(e) => e.key === 'Enter' && handleAuditLogFilter()}
          />
          <button on:click={handleAuditLogFilter}>Filter</button>
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
    {:else if activeTab === 'users'}
      <div class="users">
        <h2>Users</h2>
        {#if loading.users}
          <div>Loading...</div>
        {:else}
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Role</th>
                <th>Active</th>
                <th>Created At</th>
                <th>Last Login</th>
              </tr>
            </thead>
            <tbody>
              {#each users as user}
                <tr>
                  <td>{user.id}</td>
                  <td>{user.email}</td>
                  <td>{user.role}</td>
                  <td>{user.is_active ? 'Yes' : 'No'}</td>
                  <td>{formatDate(user.created_at)}</td>
                  <td>{formatDate(user.last_login)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
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
              <input type="checkbox" bind:checked={writeMode} on:change={toggleWriteMode} />
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
              autofocus
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

        <div class="cli-output" bind:this={cliOutputElement}>
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
    {/if}
  </div>
  {/if}
</div>

<style>
  .console-container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
  }

  h1 {
    color: var(--text-primary);
    margin-bottom: 2rem;
  }

  h2 {
    color: var(--text-primary);
    margin-top: 2rem;
    margin-bottom: 1rem;
  }

  h3 {
    color: var(--text-primary);
    margin-top: 1.5rem;
    margin-bottom: 0.5rem;
  }

  .tabs {
    display: flex;
    gap: 0.5rem;
    border-bottom: 2px solid var(--border-color);
    margin-bottom: 2rem;
  }

  .tabs button {
    padding: 0.75rem 1.5rem;
    background: none;
    border: none;
    border-bottom: 3px solid transparent;
    cursor: pointer;
    color: var(--text-secondary);
    transition: all 0.2s;
  }

  .tabs button:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary);
  }

  .tabs button.active {
    color: var(--accent-color);
    border-bottom-color: var(--accent-color);
    font-weight: bold;
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
    padding: 1rem;
    background: var(--bg-tertiary);
    border-radius: 4px;
  }

  .status-badge {
    display: inline-block;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    background: var(--error-color);
    color: white;
    font-weight: bold;
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
    padding: 1rem;
    background: var(--bg-tertiary);
    border-radius: 4px;
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
    padding: 1rem;
    background: var(--bg-tertiary);
    border-radius: 4px;
  }

  .activity-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    color: var(--text-primary);
  }

  .info-section {
    padding: 1rem;
    background: var(--bg-tertiary);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    color: var(--text-primary);
  }

  .api-test-section {
    padding: 1rem;
    background: var(--bg-tertiary);
    border-radius: 4px;
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
    padding: 0.5rem 1rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: 500;
    transition: background 0.2s;
  }

  .test-api-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .test-api-btn:disabled {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    cursor: not-allowed;
  }

  .api-test-result {
    padding: 0.75rem;
    border-radius: 4px;
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

  .filters {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .filters input {
    padding: 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    color: var(--text-primary);
    flex: 1;
  }

  .filters button {
    padding: 0.5rem 1rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1rem;
    background: var(--bg-tertiary);
  }

  th {
    background: var(--bg-secondary);
    color: var(--text-primary);
    padding: 0.75rem;
    text-align: left;
    border-bottom: 2px solid var(--border-color);
  }

  td {
    padding: 0.75rem;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border-color);
  }

  tr:hover {
    background: var(--bg-secondary);
  }

  .pagination {
    display: flex;
    gap: 1rem;
    align-items: center;
    justify-content: center;
    margin-top: 1rem;
  }

  .pagination button {
    padding: 0.5rem 1rem;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .pagination button:disabled {
    background: var(--bg-tertiary);
    color: var(--text-tertiary);
    cursor: not-allowed;
  }

  .pagination span {
    color: var(--text-primary);
  }

  .error-message {
    padding: 1rem;
    background: rgba(211, 47, 47, 0.2);
    color: var(--error-color);
    border: 1px solid var(--error-color);
    border-radius: 4px;
    margin-bottom: 2rem;
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

  .autocomplete-item strong {
    color: #00ff00;
    display: block;
    margin-bottom: 0.25rem;
    font-family: inherit;
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
</style>

