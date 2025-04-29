import { useAuthStore } from '../stores/useAuthStore';

// const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4444';
const API_BASE = 'http://localhost:4444';

export async function searchSecrets(query: string, projectKey?: string) {
  const { apiKey, projectKey: defaultKey } = useAuthStore.getState();
  const res = await fetch(`${API_BASE}/search`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "x-project-key": projectKey || defaultKey,
    },
    body: JSON.stringify({ query }),      // <-- sends a string now
  });
  if (!res.ok) throw new Error("Failed to search secrets");
  return res.json();
}

export async function getSecret(secretKey: string, projectKey?: string | null) {
  const { apiKey } = useAuthStore.getState();

  const res = await fetch(`${API_BASE}/secrets/${secretKey}`, {
    headers: {
      'x-api-key': apiKey,
      ...(projectKey ? { 'x-project-key': projectKey } : {}),
    },
  });

  if (!res.ok) throw new Error('Failed to fetch secret');
  return await res.json();
}

export async function upsertSecret(secretKey: string, secretValue: any, projectKey?: string) {
  const { apiKey, projectKey: defaultProjectKey } = useAuthStore.getState();

  const response = await fetch(`${API_BASE}/secrets/${secretKey}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "x-project-key": projectKey || defaultProjectKey,
    },
    body: JSON.stringify({ value: secretValue }),
  });

  if (!response.ok) throw new Error("Failed to upsert secret");
}

export async function deleteSecret(secretKey: string, projectKey?: string | null) {
  const { apiKey, projectKey: storeProjectKey } = useAuthStore.getState();
  const res = await fetch(`${API_BASE}/secrets/${secretKey}`, {
    method: 'DELETE',
    headers: {
      'x-api-key': apiKey,
      'x-project-key': projectKey || storeProjectKey,
    },
  });
  if (!res.ok) throw new Error('Failed to delete secret');
}