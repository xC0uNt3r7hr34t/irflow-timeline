import { createContext, useContext } from "react";

export const ProcessAnalyzerContext = createContext(null);

export function useProcessAnalyzerContext() {
  const ctx = useContext(ProcessAnalyzerContext);
  if (!ctx) throw new Error("useProcessAnalyzerContext must be used within <ProcessAnalyzerProvider>");
  return ctx;
}
