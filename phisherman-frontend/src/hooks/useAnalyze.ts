import { useState } from 'react';
import { AnalysisResponse, AnalysisRequest, ApiError } from '@/types/api';

interface UseAnalyzeState {
  data: AnalysisResponse | null;
  loading: boolean;
  error: string | null;
}

export const useAnalyze = () => {
  const [state, setState] = useState<UseAnalyzeState>({
    data: null,
    loading: false,
    error: null,
  });

  const analyze = async (url: string) => {
    setState({ data: null, loading: true, error: null });

    try {
      const response = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url } satisfies AnalysisRequest),
      });

      if (!response.ok) {
        const errorData: ApiError = await response.json();
        throw new Error(errorData.error.message || 'Error en el análisis');
      }

      const data: AnalysisResponse = await response.json();
      setState({ data, loading: false, error: null });
    } catch (error) {
      setState({
        data: null,
        loading: false,
        error: error instanceof Error ? error.message : 'Error desconocido'
      });
    }
  };

  return {
    ...state,
    analyze,
  };
};
