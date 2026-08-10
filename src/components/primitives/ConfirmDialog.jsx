import useConfirmStore from "../../store/useConfirmStore.js";
import useTheme from "../../hooks/useTheme.js";
import Modal from "./Modal.jsx";
import Button from "./Button.jsx";

/**
 * Themed confirmation dialog. Listens to `useConfirmStore` for the active
 * prompt and renders a Modal-based confirmation UI. Mount once at app root.
 *
 * Replaces window.confirm() calls — see `useConfirmStore.js` for the API.
 */
export default function ConfirmDialog() {
  const prompt = useConfirmStore((s) => s.prompt);
  const resolve = useConfirmStore((s) => s.resolve);
  const { th } = useTheme();

  if (!prompt) return null;

  const { title, message, confirmLabel, cancelLabel, destructive } = prompt;

  return (
    <Modal
      open
      title={title || "Confirm"}
      onClose={() => resolve(false)}
      width={420}
      zIndex={300}
      footer={(
        <>
          <Button variant="secondary" onClick={() => resolve(false)}>{cancelLabel}</Button>
          <Button
            variant={destructive ? "dangerSoft" : "primary"}
            onClick={() => resolve(true)}
            autoFocus
          >
            {confirmLabel}
          </Button>
        </>
      )}
    >
      <div style={{
        color: th.text, fontSize: 13, lineHeight: 1.5,
        fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
        whiteSpace: "pre-wrap", wordBreak: "break-word",
      }}>
        {message}
      </div>
    </Modal>
  );
}
