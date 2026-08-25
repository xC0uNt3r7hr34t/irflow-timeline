---
description: About the author of IRFlow Timeline — Renzon Cruz, DFIR investigator and developer.
---

# About the Author

<script setup>
import { withBase } from 'vitepress'
</script>

<div style="display: flex; gap: 32px; align-items: flex-start; flex-wrap: wrap; margin: 24px 0;">
  <div style="flex-shrink: 0;">
    <img :src="withBase('/author.jpg')" alt="Renzon Cruz" style="width: 180px; height: 180px; border-radius: 50%; object-fit: cover; border: 3px solid var(--vp-c-brand-1);" />
  </div>
  <div style="flex: 1; min-width: 280px;">
    <h2 style="margin-top: 0;">Renzon Cruz</h2>
    <p style="font-size: 1.1em; color: var(--vp-c-text-2); margin-top: -8px;">
      Technical Director, Incident Response<br>
      <strong style="color: var(--vp-c-brand-1);">Unit 42 — Palo Alto Networks</strong>
    </p>
    <div class="author-socials">
      <a href="https://www.linkedin.com/in/renzoncruz/" target="_blank" rel="noopener" class="author-social-icon" aria-label="LinkedIn" title="LinkedIn">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" role="img">
          <path fill="#0A66C2" d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
        </svg>
      </a>
      <a href="https://x.com/r3nzsec" target="_blank" rel="noopener" class="author-social-icon author-social-icon-x" aria-label="X" title="X">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" role="img">
          <path fill="currentColor" d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
        </svg>
      </a>
      <a href="mailto:renzoncruz.26@gmail.com" class="author-social-icon" aria-label="Email via Gmail" title="Email">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" role="img">
          <path fill="#EA4335" d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L5.455 4.64 12 9.548l6.545-4.91 1.528-1.145C21.69 2.28 24 3.434 24 5.457z"/>
        </svg>
      </a>
    </div>
  </div>
</div>

<style>
.author-socials {
  display: flex;
  gap: 10px;
  margin-top: 12px;
  align-items: center;
}
.author-social-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
  text-decoration: none;
  transition: background 0.2s ease, transform 0.2s ease;
}
.author-social-icon:hover {
  background: var(--vp-c-brand-soft);
  transform: translateY(-1px);
}
.author-social-icon-x {
  color: var(--vp-c-text-1);
}
</style>

---

## Background

Renzon Cruz is a seasoned Digital Forensics and Incident Response (DFIR) professional with **8 years of experience** investigating complex cyber intrusions across enterprise environments. He currently serves as **Technical Director of Incident Response at Unit 42, Palo Alto Networks**, where he leads high-profile breach investigations and threat actor negotiation.

Prior to Unit 42, Renzon was a **Senior Consultant at the National Cybersecurity Agency**, where he responded to nation-state and advanced persistent threat (APT) campaigns targeting critical infrastructure.

## Community Contributions

Renzon is an active contributor to the DFIR community:

- **DFIR Analyst/Contributor** at [The DFIR Report](https://thedfirreport.com/) — providing detailed intrusion analysis write-ups used by defenders worldwide
- **CFP Board & APT Labs Contributor** at [Xintra APT Labs](https://www.xintra.org/) — developing hands-on APT investigation training scenarios
- **Co-Founder/Lead Instructor** at GuideM — lead author of Cyber Defense & Threat Hunting, and Digital Forensics & Memory Analysis courses.

## Why IRFlow Timeline?

If you’re a DFIR analyst running macOS, you know the struggle of booting up a Windows VM just to triage a timeline. I got tired of it, so I built a solution.

Introducing **IRFlow Timeline**.

It’s a tool built from the ground up based on real-world IR experience. Every feature exists because I reached for it during an actual case, and it wasn’t there.

If you need to stay agile in the field without leaving your native OS, this is for you.

— Renzon Cruz





