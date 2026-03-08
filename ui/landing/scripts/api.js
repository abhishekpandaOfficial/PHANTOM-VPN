import { state } from './state.js';

export async function publicApi(path, opts = {}) {
  const res = await fetch(state.apiRoot + path, {
    method: opts.method || 'GET',
    headers: opts.body ? { 'Content-Type': 'application/json' } : undefined,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });

  let data = {};
  try {
    data = await res.json();
  } catch (error) {
    data = {};
  }

  if (!res.ok) throw new Error(data.error || (`HTTP ${res.status}`));
  return data;
}

export function createTrialProfile(payload) {
  return publicApi('/api/public/trial', {
    method: 'POST',
    body: payload,
  });
}

export function fetchPublicUser(userId) {
  return publicApi(`/api/public/users/${encodeURIComponent(userId)}`);
}
