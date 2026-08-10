import { useMemo } from "react";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useAnalystProfile from "./hooks/useAnalystProfile.js";
import useProcessAnalystEntries from "./hooks/useProcessAnalystEntries.js";
import useProcessSourceEvent from "./hooks/useProcessSourceEvent.js";
import useProcessRelatedEvents from "./hooks/useProcessRelatedEvents.js";
import { ProcessAnalyzerContext } from "./ProcessAnalyzerContext.js";

export default function ProcessAnalyzerProvider({ activeFilters, children }) {
  const ct = useCurrentTab();
  const { piAnalystProfile, setPiAnalystProfile } = useAnalystProfile();
  const { upsertPiAnalystEntry, removePiAnalystEntry, makePiAnalystEntry } = useProcessAnalystEntries();
  const openPiSourceEvent = useProcessSourceEvent(ct?.id);
  useProcessRelatedEvents(ct?.id);

  const value = useMemo(() => ({
    piAnalystProfile,
    setPiAnalystProfile,
    upsertPiAnalystEntry,
    removePiAnalystEntry,
    makePiAnalystEntry,
    openPiSourceEvent,
    activeFilters,
  }), [piAnalystProfile, setPiAnalystProfile, upsertPiAnalystEntry, removePiAnalystEntry, makePiAnalystEntry, openPiSourceEvent, activeFilters]);

  return (
    <ProcessAnalyzerContext.Provider value={value}>
      {children}
    </ProcessAnalyzerContext.Provider>
  );
}
