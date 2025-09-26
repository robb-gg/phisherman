import { useState } from 'react';

interface SearchFormProps {
  onSearch: (url: string) => void;
  loading: boolean;
}

export const SearchForm = ({ onSearch, loading }: SearchFormProps) => {
  const [url, setUrl] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || loading) return;
    onSearch(url.trim());
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="relative">
        <div className="flex items-center border border-gray-300 rounded-full shadow-sm hover:shadow-md focus-within:shadow-md transition-shadow duration-200 bg-white">
          {/* Ícono de búsqueda */}
          <div className="pl-4 pr-3">
            <svg
              className="h-5 w-5 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
          </div>

          {/* Input principal */}
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Introduce una URL para analizar..."
            className="flex-1 py-3 px-2 text-base text-gray-900 placeholder-gray-500 bg-transparent border-none outline-none"
            disabled={loading}
          />

          {/* Botón de análisis */}
          <button
            type="submit"
            disabled={!url.trim() || loading}
            className="mr-2 px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-full hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Analizando...</span>
              </div>
            ) : (
              'Analizar'
            )}
          </button>
        </div>
      </div>

      {/* Sugerencias rápidas */}
      <div className="mt-4 text-center">
        <div className="text-xs text-gray-500 mb-2">Prueba con:</div>
        <div className="flex flex-wrap justify-center gap-2">
          {[
            'https://google.com',
            'http://phishing-example.com',
            'https://suspicious-site.net',
          ].map((example) => (
            <button
              key={example}
              type="button"
              onClick={() => !loading && setUrl(example)}
              className="px-3 py-1 text-xs text-blue-600 bg-blue-50 rounded-full hover:bg-blue-100 transition-colors disabled:opacity-50"
              disabled={loading}
            >
              {example}
            </button>
          ))}
        </div>
      </div>
    </form>
  );
};
