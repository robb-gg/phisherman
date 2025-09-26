// Types para la API de Phisherman
export interface AnalyzerResult {
  name: string;
  score: number;
  confidence: number;
  labels: string[];
  evidence: Record<string, any>;
  execution_time_ms: number;
  error?: string;
}

export interface AnalysisResponse {
  url: string;
  malicious: boolean;
  score: number;
  confidence: number;
  labels: string[];
  evidence: Record<string, any>;
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
