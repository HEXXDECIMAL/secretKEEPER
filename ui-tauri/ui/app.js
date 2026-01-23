const { invoke } = window.__TAURI__.tauri;
const { listen } = window.__TAURI__.event;

// State
let currentView = 'dashboard';
let violations = [];
let exceptions = [];
let categories = [];
let selectedViolation = null;
let status = null;

// DOM Elements
const views = {
    dashboard: document.getElementById('dashboard-view'),
    history: document.getElementById('history-view'),
    exceptions: document.getElementById('exceptions-view'),
    settings: document.getElementById('settings-view')
};

const modals = {
    violation: document.getElementById('violation-modal'),
    exception: document.getElementById('exception-modal')
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupSettingsTabs();
    setupModals();
    setupForms();
    setupEventListeners();
    refreshStatus();
    refreshViolations();
    refreshExceptions();
    refreshCategories();
});

// Navigation
function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.dataset.view;
            navigateTo(view);
        });
    });
}

function navigateTo(view) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.view === view);
    });

    // Update views
    Object.entries(views).forEach(([key, el]) => {
        el.classList.toggle('active', key === view);
    });

    currentView = view;

    // Refresh data when switching views
    if (view === 'history') refreshViolations();
    if (view === 'exceptions') refreshExceptions();
    if (view === 'settings') {
        refreshCategories();
        refreshStatus();
    }
}

// Settings Tabs
function setupSettingsTabs() {
    document.querySelectorAll('.settings-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.dataset.tab;

            // Update tab buttons
            document.querySelectorAll('.settings-tab').forEach(t => {
                t.classList.toggle('active', t.dataset.tab === tabId);
            });

            // Update tab content
            document.querySelectorAll('.settings-tab-content').forEach(content => {
                content.classList.toggle('active', content.id === `settings-${tabId}`);
            });
        });
    });
}

// Modals
function setupModals() {
    // Close on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
        backdrop.addEventListener('click', () => {
            closeAllModals();
        });
    });

    // Close buttons
    document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
        btn.addEventListener('click', () => {
            closeAllModals();
        });
    });

    // Violation modal actions
    document.getElementById('modal-kill').addEventListener('click', async () => {
        if (selectedViolation) {
            await killProcess(selectedViolation.id);
            closeAllModals();
        }
    });

    document.getElementById('modal-allow-once').addEventListener('click', async () => {
        if (selectedViolation) {
            await allowOnce(selectedViolation.id);
            closeAllModals();
        }
    });

    document.getElementById('modal-allow-always').addEventListener('click', async () => {
        if (selectedViolation) {
            await allowPermanently(selectedViolation.id);
            closeAllModals();
        }
    });

    document.getElementById('modal-exception').addEventListener('click', () => {
        if (selectedViolation) {
            showExceptionModal(selectedViolation);
        }
    });

    // Resume button for stopped parent processes
    document.getElementById('modal-resume').addEventListener('click', async () => {
        if (selectedViolation) {
            const stoppedParent = findStoppedParent(selectedViolation.process_tree);
            if (stoppedParent) {
                await resumeProcess(stoppedParent.pid);
                closeAllModals();
            }
        }
    });
}

function showModal(modalId) {
    const modal = modals[modalId];
    if (modal) {
        modal.classList.remove('hidden');
    }
}

function closeAllModals() {
    Object.values(modals).forEach(modal => {
        modal.classList.add('hidden');
    });
    selectedViolation = null;
}

// Forms
function setupForms() {
    // Exception type toggle
    document.querySelectorAll('input[name="exception-type"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            document.getElementById('process-path-group').classList.toggle('hidden', e.target.value !== 'process');
            document.getElementById('code-signer-group').classList.toggle('hidden', e.target.value !== 'signer');
        });
    });

    // Permanent toggle
    document.getElementById('is-permanent').addEventListener('change', (e) => {
        document.getElementById('expiration-group').style.display = e.target.checked ? 'none' : 'block';
    });

    // Save exception
    document.getElementById('save-exception').addEventListener('click', async () => {
        await saveException();
    });

    // Add exception button
    document.getElementById('add-exception-btn').addEventListener('click', () => {
        showExceptionModal();
    });
}

// Event listeners
function setupEventListeners() {
    // Refresh buttons
    document.getElementById('refresh-history').addEventListener('click', refreshViolations);
    document.getElementById('reconnect-btn').addEventListener('click', reconnect);

    // Export button
    document.getElementById('export-history').addEventListener('click', exportViolations);

    // Mode radio buttons
    document.querySelectorAll('input[name="mode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            setMode(e.target.value);
        });
    });

    // Search
    document.getElementById('history-search').addEventListener('input', (e) => {
        filterViolations(e.target.value);
    });

    // Listen for Tauri events
    listen('violation', (event) => {
        handleNewViolation(event.payload);
    });

    listen('navigate', (event) => {
        navigateTo(event.payload);
    });
}

// API calls
async function refreshStatus() {
    try {
        status = await invoke('get_status');
        updateStatusDisplay();
        updateConnectionStatus(true);
    } catch (e) {
        console.error('Failed to get status:', e);
        updateConnectionStatus(false);
    }
}

async function refreshViolations() {
    try {
        violations = await invoke('get_violations', { limit: 100 });
        renderViolations();
        renderRecentViolations();
    } catch (e) {
        console.error('Failed to get violations:', e);
    }
}

async function refreshExceptions() {
    try {
        exceptions = await invoke('get_exceptions');
        renderExceptions();
    } catch (e) {
        console.error('Failed to get exceptions:', e);
    }
}

async function refreshCategories() {
    try {
        categories = await invoke('get_categories');
        renderCategories();
    } catch (e) {
        console.error('Failed to get categories:', e);
        // Show empty state
        document.getElementById('categories-list').innerHTML =
            '<div class="empty-state">Could not load categories</div>';
    }
}

async function setMode(mode) {
    try {
        await invoke('set_mode', { mode });
        refreshStatus();
    } catch (e) {
        console.error('Failed to set mode:', e);
    }
}

async function setCategoryEnabled(categoryId, enabled) {
    try {
        await invoke('set_category_enabled', { categoryId, enabled });
    } catch (e) {
        console.error('Failed to set category enabled:', e);
    }
}

async function allowOnce(eventId) {
    try {
        await invoke('allow_once', { eventId });
    } catch (e) {
        console.error('Failed to allow once:', e);
    }
}

async function allowPermanently(eventId) {
    try {
        await invoke('allow_permanently', { eventId, expiresHours: null, comment: null });
    } catch (e) {
        console.error('Failed to allow permanently:', e);
    }
}

async function killProcess(eventId) {
    try {
        await invoke('kill_process', { eventId });
    } catch (e) {
        console.error('Failed to kill process:', e);
    }
}

async function resumeProcess(pid) {
    try {
        await invoke('resume_process', { pid });
    } catch (e) {
        console.error('Failed to resume process:', e);
    }
}

async function saveException() {
    const type = document.querySelector('input[name="exception-type"]:checked').value;
    const filePattern = document.getElementById('file-pattern').value;
    const isGlob = document.getElementById('is-glob').checked;
    const isPermanent = document.getElementById('is-permanent').checked;
    const comment = document.getElementById('comment').value || null;

    const processPath = type === 'process' ? document.getElementById('process-path').value : null;
    const signerValue = type === 'signer' ? document.getElementById('code-signer').value : null;
    const signerType = signerValue ? 'signing_id' : null;
    const signingId = signerValue;
    const teamId = null;
    const expiresHours = isPermanent ? null : parseInt(document.getElementById('expires-hours').value);

    try {
        await invoke('add_exception', {
            processPath,
            signerType,
            teamId,
            signingId,
            filePattern,
            isGlob,
            expiresHours,
            comment
        });
        closeAllModals();
        refreshExceptions();
    } catch (e) {
        console.error('Failed to save exception:', e);
        alert('Failed to save exception: ' + e);
    }
}

async function removeException(id) {
    try {
        await invoke('remove_exception', { id });
        refreshExceptions();
    } catch (e) {
        console.error('Failed to remove exception:', e);
    }
}

async function reconnect() {
    try {
        await invoke('reconnect');
        refreshStatus();
    } catch (e) {
        console.error('Failed to reconnect:', e);
        updateConnectionStatus(false);
    }
}

async function exportViolations() {
    try {
        const json = await invoke('export_violations', { limit: 1000 });

        // Create download
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `secretkeeper-violations-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        console.error('Failed to export violations:', e);
        alert('Failed to export: ' + e);
    }
}

// Rendering
function updateStatusDisplay() {
    if (status) {
        const modeDisplay = status.mode.replace('-', ' ');
        document.getElementById('stat-mode').textContent = modeDisplay.charAt(0).toUpperCase() + modeDisplay.slice(1);
        document.getElementById('stat-uptime').textContent = formatUptime(status.uptime_secs);
        document.getElementById('stat-violations').textContent = status.total_violations.toLocaleString();
        document.getElementById('stat-pending').textContent = status.events_pending.toLocaleString();

        // Update mode radio
        const modeRadio = document.querySelector(`input[name="mode"][value="${status.mode}"]`);
        if (modeRadio) modeRadio.checked = true;

        // Update agent status card
        const statusDot = document.getElementById('agent-status-dot');
        const statusText = document.getElementById('agent-status-text');
        const modeBadge = document.getElementById('agent-mode-badge');

        if (status.degraded_mode) {
            statusDot.className = 'status-dot limited';
            statusText.textContent = 'Limited Protection';
        } else {
            statusDot.className = 'status-dot connected';
            statusText.textContent = 'Protected';
        }

        modeBadge.textContent = modeDisplay.charAt(0).toUpperCase() + modeDisplay.slice(1);
        modeBadge.className = `badge badge-${status.mode === 'block' ? 'blocked' : 'logged'}`;

        // Update settings tab
        document.getElementById('settings-status-dot').className = status.degraded_mode ? 'status-dot limited' : 'status-dot connected';
        document.getElementById('settings-status-text').textContent = status.degraded_mode ? 'Limited' : 'Protected';
        document.getElementById('settings-mode').textContent = modeDisplay.charAt(0).toUpperCase() + modeDisplay.slice(1);
        document.getElementById('settings-uptime').textContent = formatUptime(status.uptime_secs);
        document.getElementById('settings-clients').textContent = status.connected_clients;
    }
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    const dot = statusEl.querySelector('.status-dot');
    const text = statusEl.querySelector('span:last-child');

    dot.classList.toggle('connected', connected);
    dot.classList.toggle('disconnected', !connected);
    text.textContent = connected ? 'Connected' : 'Disconnected';

    // Update agent status card if disconnected
    if (!connected) {
        const statusDot = document.getElementById('agent-status-dot');
        const statusText = document.getElementById('agent-status-text');
        statusDot.className = 'status-dot disconnected';
        statusText.textContent = 'Not Running';
    }
}

function renderViolations() {
    const tbody = document.getElementById('history-table-body');
    tbody.innerHTML = '';

    violations.forEach(v => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${formatTime(v.timestamp)}</td>
            <td>
                <span class="badge badge-${v.signing_status}">${getSigningDot(v.signing_status)}</span>
                ${v.process_name}
            </td>
            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${v.file_path}</td>
            <td><span class="badge badge-${v.action.toLowerCase()}">${v.action}</span></td>
            <td><span class="badge badge-${v.signing_status}">${v.signing_status}</span></td>
        `;
        tr.addEventListener('click', () => showViolationDetail(v));
        tbody.appendChild(tr);
    });
}

function renderRecentViolations() {
    const container = document.getElementById('recent-violations');

    if (violations.length === 0) {
        container.innerHTML = '<div class="empty-state">No recent violations</div>';
        return;
    }

    container.innerHTML = violations.slice(0, 5).map(v => `
        <div class="violation-row" data-id="${v.id}">
            <svg class="violation-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <div class="violation-info">
                <div class="violation-process">${v.process_name}</div>
                <div class="violation-file">${v.file_path}</div>
            </div>
            <div class="violation-time">${formatTime(v.timestamp)}</div>
            <span class="badge badge-${v.action.toLowerCase()}">${v.action}</span>
        </div>
    `).join('');

    container.querySelectorAll('.violation-row').forEach(row => {
        row.addEventListener('click', () => {
            const v = violations.find(v => v.id === row.dataset.id);
            if (v) showViolationDetail(v);
        });
    });
}

function renderExceptions() {
    const container = document.getElementById('exceptions-list');

    if (exceptions.length === 0) {
        container.innerHTML = '<div class="empty-state">No exceptions configured</div>';
        return;
    }

    container.innerHTML = exceptions.map(e => `
        <div class="exception-row">
            <div class="exception-info">
                <div class="exception-pattern">${e.file_pattern}</div>
                <div class="exception-meta">
                    ${e.process_path ? `<span>Process: ${e.process_path}</span>` : ''}
                    ${e.team_id ? `<span>Team ID: ${e.team_id}</span>` : ''}
                    ${e.signing_id ? `<span>Signing ID: ${e.signing_id}</span>` : ''}
                    <span>${e.expires_at ? `Expires: ${formatDate(e.expires_at)}` : 'Permanent'}</span>
                    <span>Added by ${e.added_by}</span>
                </div>
            </div>
            <div class="exception-actions">
                <button class="btn btn-danger btn-sm" onclick="removeException(${e.id})">Remove</button>
            </div>
        </div>
    `).join('');
}

function renderCategories() {
    const container = document.getElementById('categories-list');

    if (categories.length === 0) {
        container.innerHTML = '<div class="empty-state">No categories available</div>';
        return;
    }

    container.innerHTML = categories.map(c => `
        <div class="category-row">
            <label class="category-toggle">
                <input type="checkbox" ${c.enabled ? 'checked' : ''}
                       onchange="setCategoryEnabled('${c.id}', this.checked)">
                <span class="category-icon">${getCategoryIcon(c.id)}</span>
                <div class="category-info">
                    <div class="category-name">${formatCategoryName(c.id)}</div>
                    <div class="category-patterns">${c.patterns.join(', ')}</div>
                </div>
            </label>
        </div>
    `).join('');
}

function showViolationDetail(violation) {
    selectedViolation = violation;
    const container = document.getElementById('violation-detail');

    // Check for stopped parent process
    const stoppedParent = findStoppedParent(violation.process_tree);
    const resumeBtn = document.getElementById('modal-resume');
    if (stoppedParent) {
        resumeBtn.style.display = 'inline-flex';
        resumeBtn.textContent = `Resume ${stoppedParent.name} (PID ${stoppedParent.pid})`;
    } else {
        resumeBtn.style.display = 'none';
    }

    container.innerHTML = `
        <div class="detail-section">
            <h3>Protected File</h3>
            <div class="detail-row">
                <span class="detail-label">Path</span>
                <span class="detail-value">${violation.file_path}</span>
            </div>
            ${violation.rule_id ? `
            <div class="detail-row">
                <span class="detail-label">Rule</span>
                <span class="detail-value">${violation.rule_id}</span>
            </div>
            ` : ''}
        </div>

        <div class="detail-section">
            <h3>Process Information</h3>
            <div class="detail-row">
                <span class="detail-label">Path</span>
                <span class="detail-value">${violation.process_path}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">PID</span>
                <span class="detail-value">${violation.process_pid}</span>
            </div>
            ${violation.parent_pid ? `
            <div class="detail-row">
                <span class="detail-label">Parent PID</span>
                <span class="detail-value">${violation.parent_pid}</span>
            </div>
            ` : ''}
            ${violation.process_cmdline ? `
            <div class="detail-row">
                <span class="detail-label">Command</span>
                <span class="detail-value">${violation.process_cmdline}</span>
            </div>
            ` : ''}
        </div>

        ${violation.team_id || violation.signing_id ? `
        <div class="detail-section">
            <h3>Code Signing</h3>
            ${violation.team_id ? `
            <div class="detail-row">
                <span class="detail-label">Team ID</span>
                <span class="detail-value">${violation.team_id}</span>
            </div>
            ` : ''}
            ${violation.signing_id ? `
            <div class="detail-row">
                <span class="detail-label">Signing ID</span>
                <span class="detail-value">${violation.signing_id}</span>
            </div>
            ` : ''}
        </div>
        ` : ''}

        <div class="detail-section">
            <h3>Process Tree</h3>
            ${renderProcessTree(violation.process_tree)}
        </div>
    `;

    showModal('violation');
}

function renderProcessTree(tree) {
    if (!tree || tree.length === 0) {
        return '<div class="empty-state">No process tree available</div>';
    }

    return `
        <div class="process-tree">
            ${tree.map((entry, index) => `
                <div class="process-tree-entry ${index === 0 ? 'violator' : ''}">
                    <div class="tree-indent">
                        ${Array(index).fill('<div class="tree-line"></div>').join('')}
                        ${index > 0 ? '<div class="tree-connector"></div>' : ''}
                    </div>
                    <span class="badge badge-${getSigningStatus(entry)}" style="margin-right: 8px;">${getSigningDot(getSigningStatus(entry))}</span>
                    <div class="process-info">
                        <div class="process-name">
                            <span class="name">${entry.name}</span>
                            <span class="pid">PID ${entry.pid}</span>
                            ${entry.ppid ? `<span class="pid">PPID ${entry.ppid}</span>` : ''}
                            ${entry.state ? `<span class="process-state state-${entry.state.toLowerCase()}">${entry.state}</span>` : ''}
                        </div>
                        <div class="process-path">${entry.path}</div>
                        <div class="process-meta">
                            ${entry.euid !== undefined ? `<span>UID ${entry.euid}</span>` : ''}
                            ${entry.cwd ? `<span>${entry.cwd}</span>` : ''}
                            ${entry.team_id ? `<span>${entry.team_id}</span>` : ''}
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function showExceptionModal(violation = null) {
    // Reset form
    document.getElementById('exception-form').reset();
    document.getElementById('process-path-group').classList.remove('hidden');
    document.getElementById('code-signer-group').classList.add('hidden');
    document.getElementById('expiration-group').style.display = 'none';

    // Pre-fill from violation if provided
    if (violation) {
        document.getElementById('process-path').value = violation.process_path || '';
        document.getElementById('code-signer').value = violation.team_id || '';

        // Default file pattern to directory
        const dir = violation.file_path.substring(0, violation.file_path.lastIndexOf('/'));
        document.getElementById('file-pattern').value = dir + '/*';
    }

    showModal('exception');
}

function filterViolations(query) {
    const filtered = query
        ? violations.filter(v =>
            v.file_path.toLowerCase().includes(query.toLowerCase()) ||
            v.process_path.toLowerCase().includes(query.toLowerCase()) ||
            v.process_name.toLowerCase().includes(query.toLowerCase())
          )
        : violations;

    const tbody = document.getElementById('history-table-body');
    tbody.innerHTML = '';

    filtered.forEach(v => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${formatTime(v.timestamp)}</td>
            <td>
                <span class="badge badge-${v.signing_status}">${getSigningDot(v.signing_status)}</span>
                ${v.process_name}
            </td>
            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${v.file_path}</td>
            <td><span class="badge badge-${v.action.toLowerCase()}">${v.action}</span></td>
            <td><span class="badge badge-${v.signing_status}">${v.signing_status}</span></td>
        `;
        tr.addEventListener('click', () => showViolationDetail(v));
        tbody.appendChild(tr);
    });
}

function handleNewViolation(violation) {
    violations.unshift(violation);
    if (currentView === 'history') {
        renderViolations();
    }
    if (currentView === 'dashboard') {
        renderRecentViolations();
    }
}

// Helpers
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour12: false });
}

function formatDate(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleDateString('en-US') + ' ' + date.toLocaleTimeString('en-US', { hour12: false });
}

function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
}

function formatCategoryName(id) {
    return id.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function getCategoryIcon(id) {
    const icons = {
        'ssh_keys': '🔑',
        'aws_credentials': '☁️',
        'gcp_credentials': '☁️',
        'azure_credentials': '☁️',
        'kubeconfig': '🎮',
        'gpg_keys': '🔐',
        'npm_tokens': '📦',
        'git_credentials': '🔀',
        'docker_config': '🐳',
        'default': '📄'
    };
    return icons[id] || icons['default'];
}

function getSigningStatus(entry) {
    if (entry.is_platform_binary) return 'platform';
    if (entry.team_id) return 'signed';
    if (entry.signing_id) return 'adhoc';
    return 'unsigned';
}

function getSigningDot(status) {
    const colors = {
        platform: '#58a6ff',
        signed: '#a371f7',
        adhoc: '#d29922',
        unsigned: '#f85149'
    };
    return `<span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${colors[status] || colors.unsigned}; margin-right: 4px;"></span>`;
}

function findStoppedParent(tree) {
    if (!tree) return null;
    // Skip first entry (the violator), look for stopped parent
    for (let i = 1; i < tree.length; i++) {
        if (tree[i].state && tree[i].state.toLowerCase() === 'stopped') {
            return tree[i];
        }
    }
    return null;
}
