'use client';

import { useState } from 'react';
import { SearchForm } from '@/components/SearchForm';
import { SearchResults } from '@/components/SearchResults';
import { useAnalyze } from '@/hooks/useAnalyze';

export default function Home() {
  const [hasSearched, setHasSearched] = useState(false);
  const { data, loading, error, analyze } = useAnalyze();

  const handleSearch = async (url: string) => {
    setHasSearched(true);
    await analyze(url);
  };

  return (
    <div className="min-h-screen bg-white">
      {/* Header simple */}
      <header className="p-4">
        <div className="flex items-center gap-4">
          <h1 className="text-xl font-medium text-gray-900">Phisherman</h1>
          <span className="text-sm text-gray-500">URL Security Scanner</span>
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
        </div>
      </main>
    </div>
  );
}
