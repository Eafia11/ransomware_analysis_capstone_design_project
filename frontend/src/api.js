const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
const API_KEY = import.meta.env.VITE_NETGUARDIAN_API_KEY || "";

function endpoint(path) {
  return `${API_BASE_URL}${path}`;
}

function authHeaders() {
  return API_KEY ? { "X-NetGuardian-Api-Key": API_KEY } : {};
}

async function parseJsonResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : { detail: await response.text() };

  if (!response.ok) {
    const message = payload.detail || payload.error || `${response.status} ${response.statusText}`;
    throw new Error(message);
  }

  return payload;
}

export async function checkHealth() {
  const response = await fetch(endpoint("/health"));
  return parseJsonResponse(response);
}

export async function uploadLogFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(endpoint("/upload"), {
    method: "POST",
    body: formData,
  });

  return parseJsonResponse(response);
}

export async function runSandboxExecutable(file, runtimeSeconds = null) {
  const formData = new FormData();
  formData.append("file", file);
  if (runtimeSeconds) {
    formData.append("runtime_seconds", String(runtimeSeconds));
  }

  const response = await fetch(endpoint("/sandbox/run"), {
    method: "POST",
    headers: authHeaders(),
    body: formData,
  });

  return parseJsonResponse(response);
}

export async function getSandboxStatus(sessionId) {
  const response = await fetch(endpoint(`/sandbox/status/${sessionId}`), {
    headers: authHeaders(),
  });
  return parseJsonResponse(response);
}

export async function analyzeFile(analysisId) {
  const response = await fetch(endpoint(`/analyze/${analysisId}`), {
    method: "POST",
  });

  return parseJsonResponse(response);
}

export async function getAnalysisResult(analysisId) {
  const response = await fetch(endpoint(`/result/${analysisId}`));
  return parseJsonResponse(response);
}

export async function generateLlmReport(analysisId) {
  const response = await fetch(endpoint(`/llm-report/${analysisId}`), {
    method: "POST",
    headers: authHeaders(),
  });

  return parseJsonResponse(response);
}
