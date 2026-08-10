Write-Host "=== IRFlow Timeline — Windows Build Script ==="

Write-Host "`n[*] Installing dependencies..."
npm install

Write-Host "`n[*] Rebuilding native modules..."
npx electron-rebuild -f -w better-sqlite3

Write-Host "`n[*] Running Vite build..."
npm run build:renderer

Write-Host "`n[*] Packaging Windows installer..."
# Core build — same as the original fork (no Hayabusa/bmc-tools required).
# Use 'npm run dist:win:full' to bundle Sigma/RDP tools first (requires Git Bash).
npm run dist:win

Write-Host "`n[✓] Build complete! Check the release/ directory."
Write-Host "    For Sigma Scan + RDP Bitmap Cache support, re-run with: npm run dist:win:full"
