const { notarize } = require("@electron/notarize");

exports.default = async function notarizing(context) {
  const { electronPlatformName, appOutDir } = context;
  if (electronPlatformName !== "darwin") return;
  if (process.env.SKIP_NOTARIZE === "1") {
    console.log("Skipping notarization because SKIP_NOTARIZE=1.");
    return;
  }

  const appleId = process.env.APPLE_ID;
  const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
  const teamId = process.env.APPLE_TEAM_ID;
  if (!appleId || !appleIdPassword || !teamId) {
    console.log("Skipping notarization because Apple notarization credentials are not set.");
    return;
  }

  const appName = context.packager.appInfo.productFilename;

  console.log("Notarizing application...");

  await notarize({
    appBundleId: "com.dfir.irflow-timeline",
    appPath: `${appOutDir}/${appName}.app`,
    appleId,
    appleIdPassword,
    teamId,
  });

  console.log("Notarization complete.");
};
