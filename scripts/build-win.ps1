Write-Host "=== IRFlow Timeline — Windows Build Script ==="

Write-Host "`n[*] Installing dependencies..."
npm install

Write-Host "`n[*] Rebuilding native modules..."
npx electron-rebuild -f -w better-sqlite3

Write-Host "`n[*] Running Vite build..."
npm run build

Write-Host "`n[*] Packaging Windows installer..."
npm run dist:win

Write-Host "`n[✓] Build complete! Check the release/ directory."