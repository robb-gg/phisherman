// Types para la API de Phisherman
export interface AnalyzerResult {
  name: string;
  score: number;
  confidence: number;
  labels: string[];
  evidence: Record<string, unknown>;
  execution_time_ms: number;
  error?: string;
}

export interface AnalysisResponse {
  url: string;
  malicious: boolean;
  score: number;
  confidence: number;
  labels: string[];
  evidence: Record<string, unknown>;
  analyzers: AnalyzerResult[];
  analysis_id?: string;
  timestamp: string;
  processing_time_ms: number;
  cached: boolean;
  version?: string;
}

export interface AnalysisRequest {
  url: string;
}

export interface ApiError {
  error: {
    code: number;
    message: string;
    type: string;
  };
}

// History types
export interface HistoryEntry {
  id: string;
  url: string;
  score: number;
  malicious: boolean;
  timestamp: string;
  labels: string[];
}
