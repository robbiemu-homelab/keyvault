interface SecretCardProps {
  secret: any;
  onEdit: (secretKey: string, projectKey?: string | null) => void;
  onDelete: () => void;
}

export function SecretCard({ secret, onEdit, onDelete }: SecretCardProps) {
  return (
    <div className="border rounded p-4 bg-white shadow">
      <pre className="text-sm">{JSON.stringify(secret, null, 2)}</pre>
      <div className="flex gap-2 mt-2">
        <button
          onClick={() => onEdit(secret.secret_key, secret.project_key)}
          className="text-blue-600 hover:underline"
        >
          Edit
        </button>
        <button
          onClick={onDelete}
          className="text-red-600 hover:underline"
        >
          Delete
        </button>
      </div>
    </div>
  );
}
