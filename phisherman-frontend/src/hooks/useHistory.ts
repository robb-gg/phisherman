import { useState, useEffect, useCallback } from 'react';
import { HistoryEntry, AnalysisResponse } from '@/types/api';

const HISTORY_KEY = 'phisherman_history';
const MAX_HISTORY_ITEMS = 20;

export function useHistory() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  // Load history from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(HISTORY_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as HistoryEntry[];
        setHistory(parsed);
      }
    } catch (error) {
      console.error('Error loading history:', error);
      setHistory([]);
    }
  }, []);

  // Save history to localStorage
  const saveHistory = useCallback((entries: HistoryEntry[]) => {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(entries));
    } catch (error) {
      console.error('Error saving history:', error);
    }
  }, []);

  // Add new entry to history
  const addEntry = useCallback((response: AnalysisResponse) => {
    const newEntry: HistoryEntry = {
      id: response.analysis_id || crypto.randomUUID(),
      url: response.url,
      score: response.score,
      malicious: response.malicious,
      timestamp: response.timestamp,
      labels: response.labels.slice(0, 3), // Keep only first 3 labels
    };

    setHistory((prev) => {
      // Remove duplicate URLs (keep the new one)
      const filtered = prev.filter((entry) => entry.url !== newEntry.url);
      // Add new entry at the beginning and limit size
      const updated = [newEntry, ...filtered].slice(0, MAX_HISTORY_ITEMS);
      saveHistory(updated);
      return updated;
    });
  }, [saveHistory]);

  // Remove entry from history
  const removeEntry = useCallback((id: string) => {
    setHistory((prev) => {
      const updated = prev.filter((entry) => entry.id !== id);
      saveHistory(updated);
      return updated;
    });
  }, [saveHistory]);

  // Clear all history
  const clearHistory = useCallback(() => {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch (error) {
      console.error('Error clearing history:', error);
    }
  }, []);

  return {
    history,
    addEntry,
    removeEntry,
    clearHistory,
  };
}

