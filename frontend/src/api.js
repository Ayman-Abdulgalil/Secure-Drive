// src/api.js
const API_BASE_URL = 'http://localhost:8000/api/v1';

export const api = {
  // Get all files
  async getFiles(params = {}) {
    const queryParams = new URLSearchParams();
    
    if (params.folder !== undefined) queryParams.append('folder', params.folder);
    if (params.search) queryParams.append('search', params.search);
    if (params.sort_by) queryParams.append('sort_by', params.sort_by);
    if (params.sort_order) queryParams.append('sort_order', params.sort_order);
    if (params.limit) queryParams.append('limit', params.limit);
    if (params.offset) queryParams.append('offset', params.offset);

    const url = `${API_BASE_URL}/files?${queryParams}`;
    const response = await fetch(url);
    
    if (!response.ok) {
      throw new Error('Failed to fetch files');
    }
    
    return await response.json();
  },

  // Get storage stats
  async getStorageStats() {
    const response = await fetch(`${API_BASE_URL}/files/stats`);
    
    if (!response.ok) {
      throw new Error('Failed to fetch storage stats');
    }
    
    return await response.json();
  },

  // Upload file
  async uploadFile(file, folder = null, logicalName = null) {
    const formData = new FormData();
    formData.append('file', file);
    if (folder) formData.append('folder', folder);
    if (logicalName) formData.append('logical_name', logicalName);

    const response = await fetch(`${API_BASE_URL}/files`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error('Failed to upload file');
    }

    return await response.json();
  },

  // Delete file
  async deleteFile(fileId) {
    const response = await fetch(`${API_BASE_URL}/files/${fileId}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error('Failed to delete file');
    }

    return await response.json();
  },

  // Download file URL
  getDownloadUrl(fileId) {
    return `${API_BASE_URL}/files/${fileId}`;
  },
};