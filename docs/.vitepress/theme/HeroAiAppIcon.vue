<template>
  <svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <!-- Claude Code — coral sunburst -->
    <g v-if="id === 'claude'">
      <circle cx="12" cy="12" r="10" :fill="brand.claude" />
      <g stroke="#F4EEE3" stroke-width="1.5" stroke-linecap="round">
        <line v-for="(ray, i) in claudeRays" :key="i" x1="12" y1="12" :x2="ray[0]" :y2="ray[1]" />
      </g>
    </g>

    <!-- OpenAI Codex — terminal prompt -->
    <g v-else-if="id === 'codex'">
      <circle cx="12" cy="12" r="10" :fill="tones(brand.codex).soft" />
      <path fill="none" :stroke="brand.codex" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M8.4 8l3.3 4-3.3 4" />
      <path fill="none" :stroke="brand.codex" stroke-width="2" stroke-linecap="round" d="M12.9 16.1h3.6" />
    </g>

    <!-- Grok Build -->
    <g v-else-if="id === 'grok'">
      <circle cx="12" cy="12" r="10" fill="#050505" />
      <path fill="#fff" d="M17.55 5.72a8.18 8.18 0 0 0-10.7-.15 8.17 8.17 0 0 0-.94 11.56l1.66-1.55a5.92 5.92 0 0 1 .78-8.29 5.91 5.91 0 0 1 7.56-.12l1.64-1.45Z" />
      <path fill="#fff" d="m3.24 20.76 11.64-9.98c.46-.39 1.15-.24 1.4.31a5.92 5.92 0 0 1-8.75 7.35l-1.66 1.55a8.18 8.18 0 0 0 12.21-10.7L21.2 2.8 10.68 14.6l-7.44 6.16Z" />
    </g>

    <!-- ChatGPT Desktop -->
    <g v-else-if="id === 'chatgpt'">
      <circle cx="12" cy="12" r="10" :fill="tones(brand.openai).soft" />
      <path :fill="brand.openai" d="M12 5.5c3.25 0 5.88 2.05 5.88 4.58 0 1.35-.72 2.58-1.85 3.35l.48 2.85-2.65-1.42a5.2 5.2 0 0 1-1.86.34c-3.25 0-5.88-2.05-5.88-4.58S8.75 5.5 12 5.5z" />
      <path :fill="tones(brand.openai).mid" d="M12 8.35c1.85 0 3.35 1.15 3.35 2.58S13.85 13.5 12 13.5s-3.35-1.15-3.35-2.58S10.15 8.35 12 8.35z" />
      <path fill="none" :stroke="brand.openai" stroke-width="1.4" stroke-linejoin="round" d="M9.2 11.1h5.6M10.1 12.65h3.8" />
    </g>

    <!-- Gemini CLI -->
    <g v-else-if="id === 'gemini'">
      <circle cx="12" cy="12" r="10" :fill="tones(brand.gemini).soft" />
      <path :fill="brand.gemini" d="M12 4.25c.4 2.85 2.55 5 5.4 5.4.4-2.85 2.55-5 5.4-5.4-.4 2.85-2.55 5-5.4 5.4-.4-2.85-2.55-5-5.4-5.4z" />
      <path :fill="tones(brand.gemini).mid" d="M12 9.35c1.45 0 2.62 1.17 2.62 2.62S13.45 14.6 12 14.6 9.38 13.43 9.38 11.97 10.55 9.35 12 9.35z" />
    </g>

    <!-- Cursor -->
    <g v-else-if="id === 'cursor'">
      <circle cx="12" cy="12" r="10" :fill="tones(brand.cursor).soft" />
      <path :fill="tones(brand.cursor).mid" d="M7.25 15.75 12 18.75l4.75-3-4.75-3-4.75 3z" />
      <path :fill="brand.cursor" d="M7.25 15.75 12 12.75V6.25L7.25 9.25v6.5z" />
      <path :fill="tones(brand.cursor).deep" d="M12 6.25l4.75 3v6.5L12 12.75V6.25z" />
      <path fill="none" :stroke="brand.cursor" stroke-width="0.85" stroke-linejoin="round" d="M12 6.25 7.25 9.25 12 12.75l4.75-3L12 6.25z" />
    </g>

    <!-- GitHub Copilot -->
    <g v-else-if="id === 'copilot'">
      <circle cx="12" cy="12" r="10" :fill="tones(brand.copilot).soft" />
      <path :stroke="brand.copilot" stroke-width="1.2" stroke-linecap="round" d="M12 8V6.3" />
      <circle cx="12" cy="5.6" r="0.95" :fill="brand.copilot" />
      <path :fill="brand.copilot" d="M6.2 12c0-2.2 2.6-3.6 5.8-3.6S17.8 9.8 17.8 12c0 2.7-2.3 4.6-5.8 4.6S6.2 14.7 6.2 12z" />
      <circle cx="9.8" cy="12.1" r="1.15" :fill="tones(brand.copilot).soft" />
      <circle cx="14.2" cy="12.1" r="1.15" :fill="tones(brand.copilot).soft" />
    </g>

    <!-- Windsurf -->
    <g v-else-if="id === 'windsurf'">
      <circle cx="12" cy="12" r="10" :fill="tones(brand.windsurf).soft" />
      <path :fill="brand.windsurf" d="M12.4 4.6c2.9 1.3 4.5 4 4.7 9.1h-4.7V4.6z" />
      <path :fill="tones(brand.windsurf).mid" d="M11.6 6.6C9.5 8 8.4 10.4 8.3 13.7h3.3V6.6z" />
      <path :stroke="brand.windsurf" stroke-width="1.15" stroke-linecap="round" d="M12 4.3v9.6" />
      <path fill="none" :stroke="brand.windsurf" stroke-width="1.3" stroke-linecap="round" d="M6.6 16.8q1.5 1.4 3 0t3 0t3 0" />
    </g>

    <!-- Continue -->
    <g v-else-if="id === 'continue'">
      <circle cx="12" cy="12" r="10" :fill="tones(brand.continue).soft" />
      <path fill="none" :stroke="tones(brand.continue).mid" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" d="M7.5 8l4 4-4 4" />
      <path fill="none" :stroke="brand.continue" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" d="M12 8l4 4-4 4" />
    </g>
  </svg>
</template>

<script setup>
/** Mirrors src/components/ai-artifact-icons.jsx (Tools → AI Artifacts → AI Apps menu). */
defineProps({
  id: { type: String, required: true },
  size: { type: Number, default: 22 },
})

const brand = {
  claude: '#D97757',
  openai: '#10A37F',
  codex: '#2F6FED',
  gemini: '#4285F4',
  cursor: '#7d8590',
  copilot: '#8b949e',
  windsurf: '#58a6ff',
  continue: '#3fb950',
}

const claudeRays = [
  [12, 5.8], [14.2, 8.2], [17.4, 8.9], [16.4, 12], [17.4, 15.1], [14.2, 15.8],
  [12, 18.2], [9.8, 15.8], [6.6, 15.1], [7.6, 12], [6.6, 8.9], [9.8, 8.2],
]

function darken(hex, f = 0.72) {
  const m = /^#?([0-9a-fA-F]{6})$/.exec(hex)
  if (!m) return hex
  const n = parseInt(m[1], 16)
  const r = Math.round(((n >> 16) & 255) * f)
  const g = Math.round(((n >> 8) & 255) * f)
  const b = Math.round((n & 255) * f)
  return `#${((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1)}`
}

function tones(c) {
  return { soft: `${c}1f`, mid: `${c}55`, deep: darken(c) }
}
</script>
