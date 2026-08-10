export const MIN_SEARCH_LENGTH = 2;

export function effectiveSearchTerm(term) {
  const value = typeof term === "string" ? term : "";
  return value.trim().length >= MIN_SEARCH_LENGTH ? value : "";
}

export function isSearchTooShort(term) {
  const length = typeof term === "string" ? term.trim().length : 0;
  return length > 0 && length < MIN_SEARCH_LENGTH;
}
