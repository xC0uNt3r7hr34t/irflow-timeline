import { lazy, Suspense } from "react";
import useUIStore from "../../store/useUIStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import ProcessAnalyzerProvider from "./ProcessAnalyzerProvider.jsx";

const ProcessTreeModal = lazy(() => import("./internals/ProcessTreeModal.jsx"));

export default function ProcessAnalyzerRoot({ activeFilters }) {
  const modal = useUIStore((s) => s.modal);
  const ct = useCurrentTab();
  return (
    <ProcessAnalyzerProvider activeFilters={activeFilters}>
      <Suspense fallback={null}>
        {modal?.type === "processTree" && ct && <ProcessTreeModal />}
      </Suspense>
    </ProcessAnalyzerProvider>
  );
}
