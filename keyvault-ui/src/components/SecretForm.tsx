import { useState } from "react";
import { upsertSecret } from "../api/secrets";


interface SecretFormProps {
  projectKey?: string | null;
  initialSecretKey?: string;
  initialSecretValue?: string;
  onSuccess: () => void;
  onCancel: () => void;
}

export function SecretForm({ projectKey, onSuccess, onCancel, initialSecretKey, initialSecretValue }: SecretFormProps) {
  const [localProjectKey, setLocalProjectKey] = useState(projectKey || "");
  const [secretKey, setSecretKey] = useState(initialSecretKey || "");
  const [secretValue, setSecretValue] = useState(initialSecretValue || "{}");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const isEdit = initialSecretKey !== undefined; // now it works

  const handleSubmit = async () => {
    setSaving(true);
    setError(null);

    try {
      await upsertSecret(secretKey, JSON.parse(secretValue), localProjectKey);
      onSuccess();
    } catch (err) {
      console.error(err);
      setError("Invalid input or server error.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-4 bg-white rounded shadow space-y-4">
      {!projectKey && (
        <input
          type="text"
          placeholder="Project Key"
          value={localProjectKey}
          onChange={(e) => setLocalProjectKey(e.target.value)}
          className="border rounded p-2 w-full"
        />
      )}
      <input
        type="text"
        placeholder="Secret Key"
        value={secretKey}
        onChange={(e) => setSecretKey(e.target.value)}
        className="border rounded p-2 w-full"
      />
      <textarea
        placeholder="Secret Value (JSON)"
        value={secretValue}
        onChange={(e) => setSecretValue(e.target.value)}
        className="border rounded p-2 w-full h-32"
      />
      {error && <div className="text-red-500">{error}</div>}
      <div className="flex gap-2">
      <button
        onClick={handleSubmit}
        className="bg-green-600 text-white rounded px-4 py-2 hover:bg-green-700"
        disabled={saving}
      >
        {isEdit ? "Update" : "Create"}
      </button>
        <button
          onClick={onCancel}
          className="bg-gray-300 text-gray-700 rounded px-4 py-2 hover:bg-gray-400"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
