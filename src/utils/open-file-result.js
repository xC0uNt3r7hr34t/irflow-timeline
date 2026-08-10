import { toast } from "../store/useToastStore.js";
import { openAiHistoryScopeModal } from "../modals/modalRegistry.js";

/**
 * Handle open-file-dialog / drag-drop import IPC results (including AI scope queue).
 */
export function handleOpenFileDialogResult(tle, setModal, result) {
  if (!result) return;
  if (result.scopePending?.length) {
    const [first, ...scopeQueue] = result.scopePending;
    setModal(openAiHistoryScopeModal({
      tool: first.tool,
      target: first.target,
      label: first.label,
      mode: "import",
      scopeQueue,
    }));
    return;
  }
  if (result === true) return;
  if (result.enqueued === 0) {
    toast.warning("Nothing to import", { detail: "No supported files were selected." });
  }
}
