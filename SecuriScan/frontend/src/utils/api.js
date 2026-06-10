const API = "";

// ── Core ─────────────────────────────────────────────────────────
export const apiFetch = async (path, options = {}, token) => {
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
};

// ── Auth ─────────────────────────────────────────────────────────
export const apiLogin = (email, password) =>
  fetch(`${API}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

export const me = (token) =>
  apiFetch("/api/auth/me", {}, token);

export const apiDownloadReport = (reportId, token) =>
  fetch(`${API}/api/report/${reportId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
  });

// ── Scans ─────────────────────────────────────────────────────────
function normalizeScan(s) {
  return {
    id:              s.scan_id      || s.id,
    target_url:      s.target       || s.target_url     || "",
    target_name:     s.target_name,
    status:          s.status       || "pending",
    progress:        s.progress     || 0,
    scan_type:       s.scan_type    || "full",
    scan_speed:      s.scan_speed   || "normal",
    created_at:      s.created_at,
    completed_at:    s.completed_at,
    created_by_email:s.created_by_email,
    finding_counts:  s.finding_counts || null,
    finding_count:   s.finding_count  || 0,
  };
}

export const getScans = (token, all = false) => apiFetch(`/api/scans${all ? "?all=true" : ""}`, {}, token).then(arr => arr.map(normalizeScan));
export const getScan        = (id, token)   => apiFetch(`/api/status/${id}`, {}, token).then(normalizeScan);
export const createScan     = (payload, token) => apiFetch("/api/scan", {
  method: "POST",
  body: JSON.stringify({
    url:        payload.target_url,
    name:       payload.name || payload.target_url,
    scan_type:  payload.scan_type,
    scan_speed: payload.scan_speed,
  }),
}, token);
export const deleteScan     = (id, token)   => apiFetch(`/api/scans/${id}`, { method:"DELETE" }, token);
export const getFindings    = (id, token)   => apiFetch(`/api/results/${id}`, {}, token).then(d => Array.isArray(d) ? d : (d.findings||[]));
export const toggleFalsePositive = (id, isFp, token) => apiFetch(`/api/findings/${id}/false-positive`, {
  method:"PATCH", body:JSON.stringify({ is_false_positive: isFp }),
}, token);

// ── Reports ───────────────────────────────────────────────────────
export const generateReport     = (scanId, token) => apiFetch(`/api/report/${scanId}`, { method:"POST", body:JSON.stringify({ format:"pdf", language:"en" }) }, token);
export const getReportDownloadUrl = (reportId)    => `${API}/api/report/${reportId}/download`;

// ── Users ─────────────────────────────────────────────────────────
export const getUsers   = (token)          => apiFetch("/api/users", {}, token);
export const createUser = (payload, token) => apiFetch("/api/users", { method:"POST", body:JSON.stringify(payload) }, token);
export const deleteUser = (id, token)      => apiFetch(`/api/users/${id}`, { method:"DELETE" }, token);
export const updateUser = (id, payload, token) => apiFetch(`/api/users/${id}`, { method:"PUT", body:JSON.stringify(payload) }, token);
