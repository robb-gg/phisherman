'use client';

import { useState, useEffect, useCallback } from 'react';
import { SearchForm } from '@/components/SearchForm';
import { SearchResults } from '@/components/SearchResults';
import { History } from '@/components/History';
import { useAnalyze } from '@/hooks/useAnalyze';
import { useHistory } from '@/hooks/useHistory';

export default function Home() {
  const [hasSearched, setHasSearched] = useState(false);
  const { data, loading, error, analyze } = useAnalyze();
  const { history, addEntry, removeEntry, clearHistory } = useHistory();

  // Add successful analysis to history
  useEffect(() => {
    if (data && !data.cached) {
      addEntry(data);
    }
  }, [data, addEntry]);

  const handleSearch = useCallback(async (url: string) => {
    setHasSearched(true);
    await analyze(url);
  }, [analyze]);

  const handleHistorySelect = useCallback((url: string) => {
    handleSearch(url);
  }, [handleSearch]);

  return (
    <div className="min-h-screen bg-white">
      {/* Header simple */}
      <header className="p-4 border-b border-gray-100">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1 className="text-xl font-medium text-gray-900">Phisherman</h1>
            <span className="text-sm text-gray-500">URL Security Scanner</span>
          </div>
          {history.length > 0 && (
            <div className="text-xs text-gray-400">
              {history.length} análisis guardados
            </div>
          )}
        </div>
      </header>

      {/* Main content */}
      <main className={`transition-all duration-300 ${hasSearched ? 'pt-8' : 'pt-32'}`}>
        <div className="max-w-2xl mx-auto px-4">
          {/* Logo/Title centrado cuando no hay búsqueda */}
          {!hasSearched && (
            <div className="text-center mb-8">
              <h2 className="text-6xl font-light text-gray-900 mb-2">🎣</h2>
              <h3 className="text-3xl font-light text-gray-900">Phisherman</h3>
              <p className="text-gray-600 mt-2">Analiza URLs sospechosas</p>
            </div>
          )}

          {/* Formulario de búsqueda */}
          <SearchForm onSearch={handleSearch} loading={loading} />

          {/* Resultados */}
          {hasSearched && (
            <div className="mt-8">
              <SearchResults data={data} loading={loading} error={error} />
            </div>
          )}

          {/* Historial - solo mostrar cuando no estamos cargando y no hay error */}
          {!loading && (
            <History
              entries={history}
              onSelect={handleHistorySelect}
              onRemove={removeEntry}
              onClear={clearHistory}
            />
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-16 py-6 border-t border-gray-100">
        <div className="max-w-2xl mx-auto px-4 text-center text-xs text-gray-400">
          <p>
            Phisherman - Análisis de URLs para detección de phishing y malware
          </p>
          <p className="mt-1">
            Tu historial se guarda localmente en tu navegador
          </p>
        </div>
      </footer>
    </div>
  );
}
