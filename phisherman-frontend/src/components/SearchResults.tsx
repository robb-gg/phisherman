import { AnalysisResponse } from '@/types/api';

interface SearchResultsProps {
  data: AnalysisResponse | null;
  loading: boolean;
  error: string | null;
}

export const SearchResults = ({ data, loading, error }: SearchResultsProps) => {
  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="inline-block w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mb-4" />
        <p className="text-gray-600">Analizando URL...</p>
        <p className="text-sm text-gray-400 mt-2">
          Ejecutando múltiples verificaciones de seguridad
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6">
        <div className="flex items-center gap-3">
          <div className="text-red-500 text-xl">❌</div>
          <div>
            <h3 className="text-red-800 font-medium">Error en el análisis</h3>
            <p className="text-red-600 text-sm mt-1">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const getScoreColor = (score: number) => {
    if (score >= 70) return 'text-red-600 bg-red-50 border-red-200';
    if (score >= 40) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
    if (score >= 0) return 'text-green-600 bg-green-50 border-green-200';
    return 'text-blue-600 bg-blue-50 border-blue-200'; // Very safe (negative scores)
  };

  const getScoreIcon = (score: number) => {
    if (score >= 70) return '🚨';
    if (score >= 40) return '⚠️';
    if (score >= 0) return '✅';
    return '🛡️'; // Very safe (negative scores)
  };

  return (
    <div className="space-y-6">
      {/* Resultado principal */}
      <div className={`border rounded-lg p-6 ${getScoreColor(data.score)}`}>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <span className="text-2xl">{getScoreIcon(data.score)}</span>
              <h3 className="text-lg font-semibold">
                {data.malicious ? 'URL Maliciosa' : 'URL Segura'}
              </h3>
            </div>
            <p className="text-sm opacity-80 mb-3">{data.url}</p>
            <div className="flex items-center gap-4 text-sm">
              <div>
                <span className="font-medium">Puntuación:</span>{' '}
                <span className="font-bold">{data.score.toFixed(1)}/100</span>
              </div>
              <div>
                <span className="font-medium">Confianza:</span>{' '}
                <span className="font-bold">
                  {(data.confidence * 100).toFixed(1)}%
                </span>
              </div>
              <div>
                <span className="font-medium">Tiempo:</span>{' '}
                <span>{data.processing_time_ms.toFixed(0)}ms</span>
              </div>
            </div>
          </div>
        </div>

        {/* Labels de riesgo */}
        {data.labels.length > 0 && (
          <div className="mt-4">
            <div className="flex flex-wrap gap-2">
              {data.labels.map((label, index) => (
                <span
                  key={index}
                  className="px-2 py-1 text-xs font-medium bg-white/50 rounded-full"
                >
                  {label}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Detalles por analizador */}
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 bg-gray-50 border-b">
          <div className="flex items-center justify-between">
            <div>
              <h4 className="text-lg font-medium text-gray-900">
                Análisis Detallado
              </h4>
              <p className="text-sm text-gray-600 mt-1">
                {data.cached ?
                  'Resultado cacheado (análisis detallado no disponible)' :
                  `Resultados de ${data.analyzers.length} analizadores`
                }
              </p>
            </div>
            {data.cached && (
              <div className="flex items-center gap-2 text-blue-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                <span className="text-sm font-medium">Caché</span>
              </div>
            )}
          </div>
        </div>

        <div className="divide-y divide-gray-200">
          {data.cached ? (
            <div className="p-6 text-center text-gray-500">
              <div className="text-4xl mb-4">⚡</div>
              <h5 className="font-medium mb-2">Resultado Cacheado</h5>
              <p className="text-sm">
                Este resultado se obtuvo del caché para mayor velocidad.<br/>
                Los detalles del análisis individual no están disponibles.
              </p>
            </div>
          ) : (
            data.analyzers.map((analyzer, index) => (
            <div key={index} className="p-6">
              <div className="flex items-start justify-between mb-3">
                <div className="flex-1">
                  <h5 className="font-medium text-gray-900 capitalize">
                    {analyzer.name.replace(/_/g, ' ')}
                  </h5>
                  {analyzer.error && (
                    <p className="text-red-600 text-sm mt-1">{analyzer.error}</p>
                  )}
                </div>
                <div className="text-right ml-4">
                  <div
                    className={`text-sm font-medium ${getScoreColor(
                      analyzer.score
                    )} px-3 py-1 rounded-full border`}
                  >
                    {analyzer.score.toFixed(1)}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {analyzer.execution_time_ms.toFixed(0)}ms
                  </div>
                </div>
              </div>

              {/* Labels del analizador */}
              {analyzer.labels.length > 0 && (
                <div className="mb-3">
                  <div className="flex flex-wrap gap-1">
                    {analyzer.labels.map((label, labelIndex) => (
                      <span
                        key={labelIndex}
                        className="px-2 py-1 text-xs text-gray-600 bg-gray-100 rounded"
                      >
                        {label}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Evidencia */}
              {analyzer.evidence &&
                Object.keys(analyzer.evidence).length > 0 && (
                  <details className="mt-3">
                    <summary className="text-sm text-gray-600 cursor-pointer hover:text-gray-800">
                      Ver evidencia ({Object.keys(analyzer.evidence).length}{' '}
                      elementos)
                    </summary>
                    <div className="mt-2 p-3 bg-gray-50 rounded text-xs">
                      <pre className="whitespace-pre-wrap text-gray-700 max-h-40 overflow-y-auto">
                        {JSON.stringify(analyzer.evidence, null, 2)}
                      </pre>
                    </div>
                  </details>
                )}
            </div>
          ))
          )}
        </div>
      </div>

      {/* Metadata */}
      <div className="bg-gray-50 rounded-lg p-4 text-xs text-gray-600">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <span className="font-medium">ID Análisis:</span>
            <div className="font-mono mt-1">{data.analysis_id}</div>
          </div>
          <div>
            <span className="font-medium">Timestamp:</span>
            <div className="mt-1">
              {new Date(data.timestamp).toLocaleString()}
            </div>
          </div>
          <div>
            <span className="font-medium">Cache:</span>
            <div className="mt-1">{data.cached ? 'Sí' : 'No'}</div>
          </div>
          <div>
            <span className="font-medium">Versión:</span>
            <div className="mt-1">{data.version || 'N/A'}</div>
          </div>
        </div>
      </div>
    </div>
  );
};
