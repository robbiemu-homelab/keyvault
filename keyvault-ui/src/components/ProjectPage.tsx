import { SearchPage } from "./SearchPage";


interface ProjectPageProps {
  projectKey: string;
}

export function ProjectPage({ projectKey }: ProjectPageProps) {
  return (
    <div className="min-h-screen bg-gray-100 text-gray-900 flex flex-col">
      <header className="bg-white shadow p-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold">🔐 KeyVault Project</h1>
        <div className="text-sm text-gray-600">
          Project: <strong>{projectKey}</strong>
        </div>
      </header>

      <main className="flex-1 p-6">
        <SearchPage projectKey={projectKey} />
      </main>

      <footer className="text-center p-4 text-xs text-gray-500">
        © {new Date().getFullYear()} KeyVault Homelab
      </footer>
    </div>
  );
}
