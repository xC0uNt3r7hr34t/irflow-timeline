Write-Host "=== IRFlow Timeline — Windows Build Script ==="

Write-Host "`n[*] Installing dependencies..."
npm install

Write-Host "`n[*] Rebuilding native modules..."
npx electron-rebuild -f -w better-sqlite3

Write-Host "`n[*] Bundling Hayabusa + bmc-tools..."
bash scripts/bundle-hayabusa.sh
bash scripts/bundle-bmc-tools.sh

Write-Host "`n[*] Running Vite build..."
npm run build:renderer

Write-Host "`n[*] Packaging Windows installer..."
npm run dist:win

Write-Host "`n[✓] Build complete! Check the release/ directory."