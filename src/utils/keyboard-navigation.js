/**
 * Return the next enabled item index, wrapping at either boundary.
 * Used by composite controls that keep focus in a search input while exposing
 * an active descendant (for example, the command palette).
 */
export function getNextEnabledIndex(items = [], currentIndex = -1, direction = 1) {
  const enabled = items
    .map((item, index) => (!item?.disabled ? index : -1))
    .filter((index) => index >= 0);
  if (enabled.length === 0) return -1;

  const currentPosition = enabled.indexOf(currentIndex);
  if (currentPosition < 0) return direction < 0 ? enabled.at(-1) : enabled[0];
  const delta = direction < 0 ? -1 : 1;
  return enabled[(currentPosition + delta + enabled.length) % enabled.length];
}
