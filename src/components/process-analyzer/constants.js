export const PT_ICON_STYLE = { width: 14, height: 14, verticalAlign: "middle", flexShrink: 0 };

// Shared Process Inspector type scale. Keep semantic roles aligned across
// Story, Triage, Hunt, Graph, Raw, and Rules instead of sizing each view ad hoc.
export const PI_TYPOGRAPHY = Object.freeze({
  heading: 13,
  title: 11,
  body: 11,
  control: 10,
  meta: 9,
  badge: 9,
  metric: 16,
});

export const PT_VIEW_MODES = {
  story:  { label: "Story",  filter: "suspicious", clustered: true, incident: true },
  triage: { label: "Triage", filter: "suspicious", clustered: true },
  hunt:   { label: "Hunt",   filter: "medium+",    clustered: true },
  graph:  { label: "Graph",  filter: "suspicious", clustered: false, graph: true },
  raw:    { label: "Raw",    filter: "all",         clustered: false },
};

export const PI_ANALYST_PROFILE_DEFAULT = { version: 1, suppressions: [], baselines: [] };
