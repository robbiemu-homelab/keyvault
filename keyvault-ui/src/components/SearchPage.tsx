import { useState, useEffect } from "react";
import { deleteSecret, getSecret, searchSecrets } from "../api/secrets";
import { SecretCard } from "./SecretCard";
import { SecretForm } from "./SecretForm";
import { Secret } from "../types/types";

interface SearchPageProps {
  /**
   * If the parent component already knows the project key, pass it here as `initialProjectKey`.
   * Otherwise, the user will be prompted to enter one.
   */
  initialProjectKey?: string | null;
}

export function SearchPage({ initialProjectKey }: SearchPageProps) {
  // Local state for the active project key
  const [projectKey, setProjectKey] = useState<string>(initialProjectKey ?? "");

  const [adding, setAdding] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Secret[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [editingSecret, setEditingSecret] = useState<{
    secretKey: string;
    projectKey?: string | null;
  } | null>(null);
  const [editingData, setEditingData] = useState<any>(null);

  // Ensure that if the prop changes, local state updates
  useEffect(() => {
    if (initialProjectKey != null) {
      setProjectKey(initialProjectKey);
    }
  }, [initialProjectKey]);

  const handleSearch = async () => {
    if (!projectKey) {
      setError("Please enter a project key.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await searchSecrets(query || "", projectKey);
      setResults(data);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Server error.");
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = async (secretKey: string, pk?: string | null) => {
    const effectiveKey = pk ?? projectKey;
    if (!effectiveKey) {
      setError("Missing project key for editing.");
      return;
    }
    try {
      const data = await getSecret(secretKey, effectiveKey);
      setEditingSecret({ secretKey, projectKey: pk });
      setEditingData(data);
    } catch (err) {
      console.error("Failed to load secret for editing", err);
      setError("Failed to load secret for editing");
    }
  };

  return (
    <div className="space-y-6">
      {/* Add/Edit modals */}
      {adding && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
          <SecretForm
            projectKey={projectKey}
            onSuccess={() => {
              setAdding(false);
              handleSearch();
            }}
            onCancel={() => setAdding(false)}
          />
        </div>
      )}
      {editingSecret && editingData && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
          <SecretForm
            projectKey={editingSecret.projectKey ?? projectKey}
            initialSecretKey={editingSecret.secretKey}
            initialSecretValue={JSON.stringify(editingData.secret_value, null, 2)}
            onSuccess={() => {
              setEditingSecret(null);
              setEditingData(null);
              handleSearch();
            }}
            onCancel={() => {
              setEditingSecret(null);
              setEditingData(null);
            }}
          />
        </div>
      )}

      {/* Search controls */}
      <div className="flex gap-2">
        {!initialProjectKey && (
          <input
            type="text"
            placeholder="Project Key"
            value={projectKey}
            onChange={(e) => setProjectKey(e.target.value)}
            className="border rounded p-2"
          />
        )}
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search secrets..."
          className="flex-1 border rounded p-2"
        />
        <button
          onClick={handleSearch}
          disabled={loading || !projectKey}
          className="bg-blue-600 text-white rounded px-4 py-2 hover:bg-blue-700 disabled:opacity-50"
        >
          Search
        </button>
      </div>

      {/* Error/Loading */}
      {error && <div className="text-red-500">{error}</div>}
      {loading && <div>Loading...</div>}

      {/* Results + New Secret */}
      {!loading && (
        <div className="space-y-4">
          <div className="grid gap-4">
            {results.map((result, idx) => (
              <SecretCard
                key={idx}
                secret={result}
                onEdit={() => handleEdit(result.secret_key, result.project_key)}
                onDelete={async () => {
                  try {
                    await deleteSecret(result.secret_key, result.project_key);
                    handleSearch();
                  } catch (err) {
                    console.error("Failed to delete secret", err);
                    setError("Failed to delete secret.");
                  }
                }}
              />
            ))}
          </div>
          <button
            onClick={() => setAdding(true)}
            className="bg-green-600 text-white rounded px-4 py-2 hover:bg-green-700"
          >
            + New Secret
          </button>
        </div>
      )}
    </div>
  );
}