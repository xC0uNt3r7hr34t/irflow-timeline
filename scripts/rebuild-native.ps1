Write-Host "Rebuilding native modules for Electron..."
npx electron-rebuild -f -w better-sqlite3
Write-Host "Done."