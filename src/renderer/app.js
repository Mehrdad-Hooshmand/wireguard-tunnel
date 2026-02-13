const { ipcRenderer } = require('electron');
const apiService = require('../services/api.js');
const QRCode = require('qrcode');

// DOM Elements
let loginPage, dashboardPage, loginForm, createModal, qrModal;
let clientsList, loadingOverlay;
let currentClients = [];

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeElements();
    setupEventListeners();
    checkAuthStatus();
});

// Initialize DOM elements
function initializeElements() {
    loginPage = document.getElementById('login-page');
    dashboardPage = document.getElementById('dashboard-page');
    loginForm = document.getElementById('login-form');
    createModal = document.getElementById('create-modal');
    qrModal = document.getElementById('qr-modal');
    clientsList = document.getElementById('clients-list');
    loadingOverlay = document.getElementById('loading-overlay');
}

// Setup all event listeners
function setupEventListeners() {
    // Login form
    loginForm.addEventListener('submit', handleLogin);
    
    // Dashboard actions
    document.getElementById('create-client-btn').addEventListener('click', showCreateModal);
    document.getElementById('refresh-btn').addEventListener('click', loadClients);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    
    // Create modal
    document.getElementById('close-create-modal').addEventListener('click', hideCreateModal);
    document.getElementById('cancel-create-btn').addEventListener('click', hideCreateModal);
    document.getElementById('create-client-form').addEventListener('submit', handleCreateClient);
    
    // QR modal
    document.getElementById('close-qr-modal').addEventListener('click', hideQRModal);
    
    // Search
    document.getElementById('search-input').addEventListener('input', handleSearch);
    
    // Close modals on outside click
    createModal.addEventListener('click', (e) => {
        if (e.target === createModal) hideCreateModal();
    });
    
    qrModal.addEventListener('click', (e) => {
        if (e.target === qrModal) hideQRModal();
    });
}

// Check if user is already authenticated
function checkAuthStatus() {
    if (apiService.isAuthenticated()) {
        showDashboard();
        loadClients();
    } else {
        showLogin();
    }
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    
    const serverURL = document.getElementById('server-url').value.trim();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    const errorElement = document.getElementById('login-error');
    const loginBtn = document.getElementById('login-btn');
    
    // Clear previous errors
    errorElement.style.display = 'none';
    
    // Disable button
    loginBtn.disabled = true;
    loginBtn.textContent = 'در حال ورود...';
    
    // Attempt login
    const result = await apiService.login(serverURL, username, password);
    
    if (result.success) {
        showDashboard();
        loadClients();
    } else {
        errorElement.textContent = result.error;
        errorElement.style.display = 'block';
    }
    
    // Re-enable button
    loginBtn.disabled = false;
    loginBtn.textContent = 'ورود';
}

// Handle logout
function handleLogout() {
    apiService.clearAuth();
    showLogin();
    
    // Clear form
    loginForm.reset();
}

// Load clients from API
async function loadClients() {
    showLoading();
    
    const result = await apiService.getClients();
    
    hideLoading();
    
    if (result.success) {
        currentClients = result.data;
        renderClients(currentClients);
        updateStatistics(currentClients);
    } else {
        showError('خطا در بارگذاری کلاینت‌ها: ' + result.error);
        
        // If unauthorized, go back to login
        if (!apiService.isAuthenticated()) {
            showLogin();
        }
    }
}

// Render clients list
function renderClients(clients) {
    const noClientsElement = document.getElementById('no-clients');
    
    if (clients.length === 0) {
        clientsList.innerHTML = '';
        noClientsElement.style.display = 'block';
        return;
    }
    
    noClientsElement.style.display = 'none';
    
    clientsList.innerHTML = clients.map(client => `
        <div class="client-card" data-client-id="${client.id}">
            <div class="client-header">
                <div class="client-name">${escapeHtml(client.name)}</div>
                <div class="client-status ${client.is_expired ? 'expired' : 'active'}">
                    ${client.is_expired ? 'منقضی شده' : 'فعال'}
                </div>
            </div>
            
            <div class="client-info">
                <div class="info-row">
                    <span class="info-label">ترافیک استفاده شده:</span>
                    <span class="info-value">${formatBytes(client.used_traffic)} / ${client.traffic_limit ? formatBytes(client.traffic_limit * 1024 * 1024 * 1024) : 'نامحدود'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">تاریخ انقضا:</span>
                    <span class="info-value">${client.expiration_date ? formatDate(client.expiration_date) : 'نامحدود'}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">تاریخ ایجاد:</span>
                    <span class="info-value">${formatDate(client.created_at)}</span>
                </div>
            </div>
            
            <div class="client-actions">
                <button class="btn btn-secondary" onclick="showQRCode(${client.id}, '${escapeHtml(client.name)}')">
                    QR Code
                </button>
                <button class="btn btn-success" onclick="downloadConfig(${client.id}, '${escapeHtml(client.name)}')">
                    دانلود
                </button>
                <button class="btn btn-danger" onclick="deleteClient(${client.id}, '${escapeHtml(client.name)}')">
                    حذف
                </button>
            </div>
        </div>
    `).join('');
}

// Update statistics
function updateStatistics(clients) {
    const totalClients = clients.length;
    const activeClients = clients.filter(c => !c.is_expired).length;
    const expiredClients = clients.filter(c => c.is_expired).length;
    
    document.getElementById('total-clients').textContent = totalClients;
    document.getElementById('active-clients').textContent = activeClients;
    document.getElementById('expired-clients').textContent = expiredClients;
}

// Handle search
function handleSearch(e) {
    const searchTerm = e.target.value.toLowerCase().trim();
    
    if (!searchTerm) {
        renderClients(currentClients);
        return;
    }
    
    const filtered = currentClients.filter(client => 
        client.name.toLowerCase().includes(searchTerm)
    );
    
    renderClients(filtered);
}

// Show create modal
function showCreateModal() {
    createModal.classList.add('active');
    document.getElementById('create-client-form').reset();
    document.getElementById('create-error').style.display = 'none';
}

// Hide create modal
function hideCreateModal() {
    createModal.classList.remove('active');
}

// Handle create client
async function handleCreateClient(e) {
    e.preventDefault();
    
    const name = document.getElementById('client-name').value.trim();
    const trafficLimit = document.getElementById('traffic-limit').value;
    const expirationDays = document.getElementById('expiration-days').value;
    
    const errorElement = document.getElementById('create-error');
    const submitBtn = document.getElementById('submit-create-btn');
    
    // Clear previous errors
    errorElement.style.display = 'none';
    
    // Validate
    if (!name) {
        errorElement.textContent = 'نام کلاینت الزامی است';
        errorElement.style.display = 'block';
        return;
    }
    
    // Disable button
    submitBtn.disabled = true;
    submitBtn.textContent = 'در حال ایجاد...';
    
    // Create client data
    const clientData = { name };
    if (trafficLimit) clientData.traffic_limit = parseInt(trafficLimit);
    if (expirationDays) clientData.expiration_days = parseInt(expirationDays);
    
    // Send request
    const result = await apiService.createClient(clientData);
    
    if (result.success) {
        hideCreateModal();
        loadClients();
    } else {
        errorElement.textContent = result.error;
        errorElement.style.display = 'block';
    }
    
    // Re-enable button
    submitBtn.disabled = false;
    submitBtn.textContent = 'ایجاد کلاینت';
}

// Show QR code for client
async function showQRCode(clientId, clientName) {
    showLoading();
    
    const result = await apiService.getClientConfig(clientId);
    
    hideLoading();
    
    if (result.success) {
        const canvas = document.getElementById('qr-canvas');
        
        try {
            await QRCode.toCanvas(canvas, result.data.config, {
                width: 300,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#ffffff'
                }
            });
            
            qrModal.classList.add('active');
        } catch (error) {
            showError('خطا در ایجاد QR Code');
        }
    } else {
        showError('خطا در دریافت کانفیگ: ' + result.error);
    }
}

// Hide QR modal
function hideQRModal() {
    qrModal.classList.remove('active');
}

// Download config file
async function downloadConfig(clientId, clientName) {
    showLoading();
    
    const result = await apiService.getClientConfig(clientId);
    
    hideLoading();
    
    if (result.success) {
        // Use IPC to save file
        ipcRenderer.invoke('download-config', {
            content: result.data.config,
            filename: `${clientName}.conf`
        });
    } else {
        showError('خطا در دانلود کانفیگ: ' + result.error);
    }
}

// Delete client
async function deleteClient(clientId, clientName) {
    const confirmed = confirm(`آیا از حذف کلاینت "${clientName}" اطمینان دارید؟`);
    
    if (!confirmed) return;
    
    showLoading();
    
    const result = await apiService.deleteClient(clientId);
    
    hideLoading();
    
    if (result.success) {
        loadClients();
    } else {
        showError('خطا در حذف کلاینت: ' + result.error);
    }
}

// UI Helper Functions
function showLogin() {
    loginPage.classList.add('active');
    dashboardPage.classList.remove('active');
}

function showDashboard() {
    loginPage.classList.remove('active');
    dashboardPage.classList.add('active');
}

function showLoading() {
    loadingOverlay.style.display = 'flex';
}

function hideLoading() {
    loadingOverlay.style.display = 'none';
}

function showError(message) {
    alert(message);
}

// Utility Functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('fa-IR');
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Make functions globally accessible
window.showQRCode = showQRCode;
window.downloadConfig = downloadConfig;
window.deleteClient = deleteClient;
