import { createContext, useContext } from "react";

export const SigmaModalContext = createContext(null);

export function useSigmaModalContext() {
  const context = useContext(SigmaModalContext);
  if (!context) throw new Error("Sigma modal context is missing");
  return context;
}
