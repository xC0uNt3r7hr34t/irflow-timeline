module.exports = {
  productName: "IRFlow Timeline",
  appId: "com.irflow.timeline",
  directories: {
    output: "release/",
    buildResources: "assets/"
  },
  files: [
    "dist/**/*",
    "electron/**/*",
    "package.json",
    "index.html"
  ],
  extraResources: [
    { from: "assets", to: "assets" }
  ],
  win: {
    target: [
      {
        target: "nsis",
        arch: ["x64"]
      }
    ],
    icon: "assets/icon.ico"
  },
  nsis: {
    oneClick: false,
    allowToChangeInstallationDirectory: true,
    perMachine: false,
    deleteAppDataOnUninstall: false
  }
};