import { cloneElement, useRef, useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import useTheme from "../../hooks/useTheme.js";

/**
 * Themed tooltip — replaces native browser `title="..."` attributes which use
 * OS-default chrome and ignore the app's glass theme.
 *
 * Usage:
 *
 *   <Tooltip content="Sort by this column">
 *     <button onClick={...}>...</button>
 *   </Tooltip>
 *
 *   <Tooltip content={<>Multi-line content also works.<br/>Use JSX freely.</>}>
 *     <button>Status</button>
 *   </Tooltip>
 *
 * Notes:
 *   - The single child must be a DOM element (button, div, span, svg) — we
 *     clone it and attach hover/focus handlers + a ref via cloneElement. This
 *     avoids a wrapper element entirely, so there are no layout side-effects.
 *   - If your child is a custom component, ensure it forwards `ref` and the
 *     hover/focus event handlers, or wrap it in a `<span>` first.
 *   - Pass `delay={0}` for an instant tooltip. Default 350ms matches OS UX.
 *   - Pass `placement="bottom"` to anchor below; default is "top" with smart
 *     auto-flip if the trigger is too close to the viewport edge.
 *   - Tooltips render into `document.body` via a portal, so they always sit
 *     above modals and menus regardless of stacking context.
 */
const SHOW_DELAY_MS = 350;
const HIDE_DELAY_MS = 80;

const composeHandler = (existing, next) => (e) => {
  if (typeof existing === "function") existing(e);
  next(e);
};

export default function Tooltip({ content, children, placement = "top", delay = SHOW_DELAY_MS, maxWidth = 320 }) {
  const { th } = useTheme();
  const triggerRef = useRef(null);
  const showTimer = useRef(null);
  const hideTimer = useRef(null);
  const [visible, setVisible] = useState(false);
  const [pos, setPos] = useState({ x: 0, y: 0, place: placement });

  const measure = useCallback(() => {
    const r = triggerRef.current?.getBoundingClientRect?.();
    if (!r) return;
    let place = placement;
    let x = r.left + r.width / 2;
    let y = placement === "top" ? r.top - 6 : r.bottom + 6;
    // Auto-flip if not enough room above
    if (placement === "top" && r.top < 56) { place = "bottom"; y = r.bottom + 6; }
    if (placement === "bottom" && r.bottom > window.innerHeight - 56) { place = "top"; y = r.top - 6; }
    // Clamp horizontally to viewport
    x = Math.max(8, Math.min(window.innerWidth - 8, x));
    setPos({ x, y, place });
  }, [placement]);

  const handleShow = useCallback(() => {
    clearTimeout(hideTimer.current);
    if (visible) return;
    showTimer.current = setTimeout(() => {
      measure();
      setVisible(true);
    }, delay);
  }, [delay, measure, visible]);

  const handleHide = useCallback(() => {
    clearTimeout(showTimer.current);
    hideTimer.current = setTimeout(() => setVisible(false), HIDE_DELAY_MS);
  }, []);

  useEffect(() => () => {
    clearTimeout(showTimer.current);
    clearTimeout(hideTimer.current);
  }, []);

  // Re-measure on scroll/resize while visible
  useEffect(() => {
    if (!visible) return;
    const onScrollOrResize = () => measure();
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    return () => {
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
    };
  }, [visible, measure]);

  // Bail out cleanly if no content (lets callers conditionally enable tooltips
  // without forking the JSX, e.g. <Tooltip content={hint}>...</Tooltip>).
  if (!content) return children;

  // Clone child to attach handlers + ref. Composes existing handlers so we
  // don't clobber whatever the trigger element already does.
  const trigger = cloneElement(children, {
    ref: (el) => {
      triggerRef.current = el;
      // Forward to existing ref if the child had one
      const childRef = children.ref;
      if (typeof childRef === "function") childRef(el);
      else if (childRef && typeof childRef === "object") childRef.current = el;
    },
    onMouseEnter: composeHandler(children.props.onMouseEnter, handleShow),
    onMouseLeave: composeHandler(children.props.onMouseLeave, handleHide),
    onFocus: composeHandler(children.props.onFocus, handleShow),
    onBlur: composeHandler(children.props.onBlur, handleHide),
  });

  const tooltipNode = visible ? (
    <div
      role="tooltip"
      style={{
        position: "fixed",
        left: pos.x,
        top: pos.y,
        transform: pos.place === "top" ? "translate(-50%, -100%)" : "translate(-50%, 0)",
        background: th.modalBg + "f2",
        border: `1px solid ${th.glassBorder}`,
        borderRadius: 6,
        padding: "5px 10px",
        color: th.text,
        fontSize: 11,
        lineHeight: 1.4,
        fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
        backdropFilter: "blur(20px) saturate(180%)",
        WebkitBackdropFilter: "blur(20px) saturate(180%)",
        boxShadow: "0 8px 24px rgba(0,0,0,0.45), 0 0 0 1px rgba(255,255,255,0.04) inset",
        zIndex: 9999,
        maxWidth,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
        pointerEvents: "none",
        animation: "tle-modal-in var(--m-fast) var(--ease-out)",
      }}
    >
      {content}
    </div>
  ) : null;

  return (
    <>
      {trigger}
      {tooltipNode && createPortal(tooltipNode, document.body)}
    </>
  );
}
