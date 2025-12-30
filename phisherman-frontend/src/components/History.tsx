import { HistoryEntry } from '@/types/api';
import { HistoryItem } from './HistoryItem';

interface HistoryProps {
  entries: HistoryEntry[];
  onSelect: (url: string) => void;
  onRemove: (id: string) => void;
  onClear: () => void;
}

export function History({ entries, onSelect, onRemove, onClear }: HistoryProps) {
  if (entries.length === 0) {
    return null;
  }

  return (
    <div className="mt-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <svg
            className="w-5 h-5 text-gray-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <h3 className="text-sm font-medium text-gray-700">
            Búsquedas recientes
          </h3>
          <span className="text-xs text-gray-400">
            ({entries.length})
          </span>
        </div>

        <button
          onClick={onClear}
          className="text-xs text-gray-500 hover:text-red-500 transition-colors"
        >
          Limpiar historial
        </button>
      </div>

      {/* History list */}
      <div className="space-y-2">
        {entries.map((entry) => (
          <HistoryItem
            key={entry.id}
            entry={entry}
            onSelect={onSelect}
            onRemove={onRemove}
          />
        ))}
      </div>

      {/* Stats summary */}
      <div className="mt-4 p-3 bg-gray-50 rounded-lg">
        <div className="flex items-center justify-between text-xs text-gray-600">
          <div className="flex items-center gap-4">
            <span>
              <span className="inline-block w-2 h-2 bg-red-500 rounded-full mr-1"></span>
              Alto riesgo: {entries.filter((e) => e.score >= 70).length}
            </span>
            <span>
              <span className="inline-block w-2 h-2 bg-yellow-500 rounded-full mr-1"></span>
              Medio: {entries.filter((e) => e.score >= 40 && e.score < 70).length}
            </span>
            <span>
              <span className="inline-block w-2 h-2 bg-green-500 rounded-full mr-1"></span>
              Seguro: {entries.filter((e) => e.score < 40).length}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
