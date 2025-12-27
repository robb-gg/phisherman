import { HistoryEntry } from '@/types/api';

interface HistoryItemProps {
  entry: HistoryEntry;
  onSelect: (url: string) => void;
  onRemove: (id: string) => void;
}

export function HistoryItem({ entry, onSelect, onRemove }: HistoryItemProps) {
  const getScoreColor = (score: number) => {
    if (score >= 70) return 'bg-red-100 text-red-700 border-red-200';
    if (score >= 40) return 'bg-yellow-100 text-yellow-700 border-yellow-200';
    return 'bg-green-100 text-green-700 border-green-200';
  };

  const getScoreIcon = (score: number) => {
    if (score >= 70) return '🚨';
    if (score >= 40) return '⚠️';
    return '✅';
  };

  const formatDate = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);

      if (diffMins < 1) return 'Ahora';
      if (diffMins < 60) return `Hace ${diffMins}m`;
      if (diffHours < 24) return `Hace ${diffHours}h`;
      if (diffDays < 7) return `Hace ${diffDays}d`;
      return date.toLocaleDateString();
    } catch {
      return '';
    }
  };

  const truncateUrl = (url: string, maxLength: number = 50) => {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
  };

  return (
    <div className="group flex items-center gap-3 p-3 bg-white border border-gray-200 rounded-lg hover:border-gray-300 hover:shadow-sm transition-all">
      {/* Score indicator */}
      <div
        className={`flex-shrink-0 w-10 h-10 flex items-center justify-center rounded-lg border ${getScoreColor(entry.score)}`}
      >
        <span className="text-sm">{getScoreIcon(entry.score)}</span>
      </div>

      {/* URL and metadata */}
      <button
        onClick={() => onSelect(entry.url)}
        className="flex-1 text-left min-w-0"
      >
        <div className="text-sm font-medium text-gray-900 truncate hover:text-blue-600 transition-colors">
          {truncateUrl(entry.url)}
        </div>
        <div className="flex items-center gap-2 mt-1">
          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${getScoreColor(entry.score)}`}>
            {entry.score.toFixed(0)}
          </span>
          <span className="text-xs text-gray-500">
            {formatDate(entry.timestamp)}
          </span>
        </div>
      </button>

      {/* Labels preview */}
      {entry.labels.length > 0 && (
        <div className="hidden sm:flex gap-1">
          {entry.labels.slice(0, 2).map((label, i) => (
            <span
              key={i}
              className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded"
            >
              {label}
            </span>
          ))}
        </div>
      )}

      {/* Remove button */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onRemove(entry.id);
        }}
        className="flex-shrink-0 p-1 text-gray-400 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-opacity"
        title="Eliminar del historial"
      >
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M6 18L18 6M6 6l12 12"
          />
        </svg>
      </button>
    </div>
  );
}

