const fs = require("fs");
const path = require("path");

const updateBaseUrlRaw =
  process.env.IRFLOW_UPDATE_BASE_URL ||
  process.env.TLE_UPDATE_BASE_URL ||
  "";

const updateBaseUrl = updateBaseUrlRaw.replace(/\/+$/, "");
const updateChannel =
  process.env.IRFLOW_UPDATE_CHANNEL ||
  process.env.TLE_UPDATE_CHANNEL ||
  "latest";

const config = {
  appId: "com.dfir.irflow-timeline",
  productName: "IRFlow Timeline",
  // Keep physical artifact names identical to electron-updater's URL-safe
  // names so manual GitHub/S3 uploads cannot publish a broken update feed.
  artifactName: "IRFlow-Timeline-${version}-${arch}.${ext}",
  mac: {
    category: "public.app-category.developer-tools",
    icon: "assets/icon.icns",
    minimumSystemVersion: "12.0",
    // Hayabusa is already universal, while better-sqlite3 13 ships architecture-named
    // Darwin prebuilds in both sub-builds. @electron/universal refuses identical Mach-O
    // files unless they are explicitly allowed, so copy these known, self-identifying
    // files through while it merges the rest of the application normally.
    x64ArchFiles: "**/{hayabusa/hayabusa,node_modules/better-sqlite3/prebuilds/darwin-*.node}",
    target: [
      {
        target: "dmg",
        arch: ["universal"],
      },
      {
        target: "zip",
        arch: ["universal"],
      },
    ],
    darkModeSupport: true,
    hardenedRuntime: true,
    gatekeeperAssess: false,
    entitlements: "entitlements.mac.plist",
    entitlementsInherit: "entitlements.mac.plist",
  },
  win: {
    target: [
      {
        target: "nsis",
        arch: ["x64"],
      },
      {
        target: "portable",
        arch: ["x64"],
      },
    ],
    icon: "assets/IRFlow-Timeline-Home.png",
    // Only disable on Linux CI cross-builds; native Windows builds embed icon/metadata normally.
    signAndEditExecutable: process.platform !== "linux",
  },
  nsis: {
    oneClick: false,
    allowToChangeInstallationDirectory: true,
    createDesktopShortcut: true,
    createStartMenuShortcut: true,
    shortcutName: "IRFlow Timeline",
    perMachine: false,
    deleteAppDataOnUninstall: false,
  },
  afterSign: process.platform === "darwin" ? "scripts/notarize.js" : undefined,
  // Notarizes + staples the DMG itself. afterSign only reaches the .app, which
  // left the downloaded disk image unsigned and Gatekeeper-rejected.
  afterAllArtifactBuild: process.platform === "darwin" ? "scripts/notarize-dmg.js" : undefined,
  electronUpdaterCompatibility: ">=2.16",
  dmg: {
    title: "IRFlow Timeline",
    contents: [
      { x: 130, y: 220 },
      { x: 410, y: 220, type: "link", path: "/Applications" },
    ],
  },
  files: [
    "dist/**/*",
    "electron/**/*",
    "assets/**/*",
  ],
  extraResources: [
    ...(fs.existsSync(path.join(__dirname, "hayabusa"))
      ? [{
          from: "hayabusa",
          to: "hayabusa",
          filter: ["**/*", "!logs/**"],
        }]
      : []),
    ...(fs.existsSync(path.join(__dirname, "tools", "bmc-tools"))
      ? [{
          from: "tools/bmc-tools",
          to: "tools/bmc-tools",
          filter: ["**/*"],
        }]
      : []),
  ],
  asarUnpack: [
    "node_modules/better-sqlite3/**",
  ],
  directories: {
    output: "release",
  },
  fileAssociations: [
    { ext: "tle", name: "IRFlow Timeline Session", description: "IRFlow Timeline Session File", role: "Editor" },
    { ext: "csv", name: "CSV File", role: "Viewer" },
    { ext: "tsv", name: "TSV File", role: "Viewer" },
    { ext: "xlsx", name: "Excel File", role: "Viewer" },
    { ext: "plaso", name: "Plaso File", role: "Viewer" },
    { ext: "sqlite", name: "SQLite Database", role: "Viewer" },
    { ext: "db", name: "SQLite Database", role: "Viewer" },
    { ext: "evtx", name: "EVTX File", role: "Viewer" },
    { ext: "mft", name: "MFT File", role: "Viewer" },
  ],
};

if (updateBaseUrl) {
  config.publish = [
    {
      provider: "generic",
      url: updateBaseUrl,
      channel: updateChannel,
      // AWS S3 supports a single byte range per GET request. The regional
      // virtual-hosted URL does not match electron-updater's built-in
      // s3.amazonaws.com heuristic, so disable multipart ranges explicitly.
      useMultipleRangeRequest: false,
    },
  ];
}

module.exports = config;
