/**
 * PassiveShield AI — Centralized Frontend API Service
 * Connects exclusively to the verified Express API Gateway endpoints on port 3001.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_PASSIVESHIELD_API_URL || 'http://localhost:3001';

async function fetchJson(url, options = {}) {
  const finalUrl = url.startsWith('http') ? url : `${API_BASE_URL}${url}`;
  try {
    const res = await fetch(finalUrl, {
      ...options,
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      cache: 'no-store'
    });
    
    if (!res.ok) {
      throw new Error(`API Error: HTTP ${res.status} ${res.statusText} at ${finalUrl}`);
    }
    
    return await res.json();
  } catch (err) {
    console.warn(`[API Client Warning] Failed request to ${finalUrl}:`, err.message);
    throw err;
  }
}

/**
 * Health probe for backend gateway
 */
export async function getSystemHealth() {
  try {
    const data = await fetchJson('/api/v1/health');
    return data?.data || { health: 'ok', uptime_seconds: 0 };
  } catch (e) {
    return { health: 'offline', uptime_seconds: 0 };
  }
}

/**
 * Operational overview metrics
 */
export async function getOperationalMetrics() {
  try {
    const data = await fetchJson('/api/v1/metrics');
    return data?.data || null;
  } catch (e) {
    return null;
  }
}

/**
 * Paginated and filtered alerts list
 */
export async function getThreatAlerts(params = {}) {
  const query = new URLSearchParams();
  if (params.severity) query.set('severity', params.severity);
  if (params.limit) query.set('limit', String(params.limit));
  if (params.offset) query.set('offset', String(params.offset));
  if (params.threat_classification) query.set('threat_classification', params.threat_classification);
  
  const queryString = query.toString() ? `?${query.toString()}` : '';
  try {
    const data = await fetchJson(`/api/v1/alerts${queryString}`);
    return data?.data || [];
  } catch (e) {
    return [];
  }
}

/**
 * Single alert detail by UUID
 */
export async function getAlertById(alertId) {
  if (!alertId) return null;
  try {
    const data = await fetchJson(`/api/v1/alerts/${encodeURIComponent(alertId)}`);
    return data?.data || null;
  } catch (e) {
    return null;
  }
}

/**
 * Active detector insights and status
 */
export async function getDetectorInsights() {
  try {
    const data = await fetchJson('/api/v1/detectors/insights');
    return data?.data || [];
  } catch (e) {
    return [];
  }
}

export const apiConfig = {
  API_BASE_URL,
  isLive: typeof window !== 'undefined'
};
