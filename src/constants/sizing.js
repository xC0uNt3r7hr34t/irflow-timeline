/**
 * Sizing scales — border-radius and font-size tokens.
 *
 * Defined to formalise the scales already dominant in the codebase. Use these
 * constants in NEW code; existing inline numeric values need not be migrated
 * unless they are off-scale (see migration policy below).
 *
 * ── Border-radius scale ─────────────────────────────────────────────────
 * r0   sharp corners (cells, dividers)
 * r2   hairline rounding (badges, micro pills)
 * r3   data-row cells, inline highlights — most-used (~25% of usage)
 * r4   inputs, small buttons
 * r6   medium buttons, tabs
 * r8   cards, sub-panels
 * r10  dropdowns, popovers
 * r12  medium modals
 * r14  analysis modals, large cards
 * pill round pills (999, equivalent to fully circular ends)
 *
 * Migration: values 1, 5, 7, 9, 16, 20 are off-scale and should be folded:
 *   1 → r2,  5 → r6,  7 → r8,  9 → r10,  16 → r14,  20 → r14
 *
 * ── Font-size scale ─────────────────────────────────────────────────────
 * f6   ultra-dense forensic indicators (rare; ProcessTreeModal severity dots)
 * f8   smallest legible label (tag pills, micro stats)
 * f9   small label (uppercase section heads, dense rows)
 * f10  default UI label — most-used
 * f11  body text, status bar
 * f12  emphasized body, button labels
 * f13  menu items, tab text
 * f14  small headings, modal field titles
 * f15  modal title (Modal primitive default)
 * f16  large stat numbers
 * f18  card stat numbers, page subheadings
 * f22  empty-state intro
 * f32  page title (empty state hero)
 *
 * Migration: half-step values (7.5, 8.5, 9.5, 10.5, 11.5, 12.5) round up to
 * the next integer (font rasterisation rounds these to integer pixel sizes
 * anyway, so the half-steps were cosmetic noise).
 */

export const R = {
  r0: 0,
  r2: 2,
  r3: 3,
  r4: 4,
  r6: 6,
  r8: 8,
  r10: 10,
  r12: 12,
  r14: 14,
  pill: 999,
};

export const F = {
  f6: 6,
  f8: 8,
  f9: 9,
  f10: 10,
  f11: 11,
  f12: 12,
  f13: 13,
  f14: 14,
  f15: 15,
  f16: 16,
  f18: 18,
  f22: 22,
  f32: 32,
};
