const axios = require('axios');

class ApiService {
  constructor() {
    this.baseURL = '';
    this.token = this.loadToken();
  }

  // Load token from localStorage
  loadToken() {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('auth_token') || '';
    }
    return '';
  }

  // Save token to localStorage
  saveToken(token) {
    if (typeof window !== 'undefined') {
      localStorage.setItem('auth_token', token);
    }
    this.token = token;
  }

  // Load server URL from localStorage
  loadServerURL() {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('server_url') || '';
    }
    return '';
  }

  // Save server URL to localStorage
  saveServerURL(url) {
    if (typeof window !== 'undefined') {
      localStorage.setItem('server_url', url);
    }
    this.baseURL = url;
  }

  // Clear auth data
  clearAuth() {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('server_url');
    }
    this.token = '';
    this.baseURL = '';
  }

  // Login
  async login(serverURL, username, password) {
    this.baseURL = serverURL;
    
    try {
      const response = await axios.post(`${serverURL}/api/login`, {
        username,
        password
      });

      if (response.data.access_token) {
        this.saveToken(response.data.access_token);
        this.saveServerURL(serverURL);
        return { success: true, data: response.data };
      }

      return { success: false, error: 'Invalid response from server' };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message || 'Login failed'
      };
    }
  }

  // Get all clients
  async getClients() {
    if (!this.token) {
      return { success: false, error: 'Not authenticated' };
    }

    try {
      const response = await axios.get(`${this.baseURL}/api/clients`, {
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      return { success: true, data: response.data };
    } catch (error) {
      if (error.response?.status === 401) {
        this.clearAuth();
      }
      return {
        success: false,
        error: error.response?.data?.detail || error.message || 'Failed to fetch clients'
      };
    }
  }

  // Create new client
  async createClient(clientData) {
    if (!this.token) {
      return { success: false, error: 'Not authenticated' };
    }

    try {
      const response = await axios.post(`${this.baseURL}/api/clients`, clientData, {
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message || 'Failed to create client'
      };
    }
  }

  // Delete client
  async deleteClient(clientId) {
    if (!this.token) {
      return { success: false, error: 'Not authenticated' };
    }

    try {
      await axios.delete(`${this.baseURL}/api/clients/${clientId}`, {
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message || 'Failed to delete client'
      };
    }
  }

  // Get client config file
  async getClientConfig(clientId) {
    if (!this.token) {
      return { success: false, error: 'Not authenticated' };
    }

    try {
      const response = await axios.get(`${this.baseURL}/api/clients/${clientId}/config`, {
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message || 'Failed to get config'
      };
    }
  }

  // Get client QR code
  async getClientQRCode(clientId) {
    if (!this.token) {
      return { success: false, error: 'Not authenticated' };
    }

    try {
      const response = await axios.get(`${this.baseURL}/api/clients/${clientId}/qr`, {
        headers: {
          'Authorization': `Bearer ${this.token}`
        },
        responseType: 'blob'
      });

      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message || 'Failed to get QR code'
      };
    }
  }

  // Update client traffic
  async updateClientTraffic(clientId, trafficGB) {
    if (!this.token) {
      return { success: false, error: 'Not authenticated' };
    }

    try {
      const response = await axios.post(
        `${this.baseURL}/api/clients/${clientId}/traffic`,
        { traffic_limit: trafficGB },
        {
          headers: {
            'Authorization': `Bearer ${this.token}`
          }
        }
      );

      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.detail || error.message || 'Failed to update traffic'
      };
    }
  }

  // Check if authenticated
  isAuthenticated() {
    return !!this.token && !!this.baseURL;
  }
}

module.exports = new ApiService();
