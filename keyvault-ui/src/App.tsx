import { useState } from "react";
import { SearchPage } from "./components/SearchPage";
import { useAuthStore } from "./stores/useAuthStore";

function App() {
  const { apiKey, setApiKey } = useAuthStore();
  const [projectKey] = useState<string | null>(null);

  if (!apiKey) {
    return (
      <div className="min-h-screen bg-gray-100 text-gray-900 flex flex-col items-center justify-center p-6">
        <div className="max-w-md w-full bg-white rounded-lg shadow p-6 space-y-4">
          <h1 className="text-xl font-bold text-center">🔐 Enter API Key</h1>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Paste your API key..."
            className="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring focus:border-blue-500"
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100 text-gray-900 flex flex-col">
      <header className="bg-white shadow p-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold">🔐 KeyVault UI</h1>
        {projectKey && (
          <div className="text-sm text-gray-600">
            Project: <strong>{projectKey}</strong>
          </div>
        )}
      </header>

      <main className="flex-1 p-6">
        <SearchPage initialProjectKey={projectKey} />
      </main>

      <footer className="text-center p-4 text-xs text-gray-500">
        © {new Date().getFullYear()} KeyVault Homelab
      </footer>
    </div>
  );
}

export default App;
