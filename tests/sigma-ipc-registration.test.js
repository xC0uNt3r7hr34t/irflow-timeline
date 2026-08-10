const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Module = require("node:module");

test("Sigma IPC handlers register with the shared application context", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-sigma-ipc-"));
  const originalLoad = Module._load;
  const originalResourcesPath = Object.getOwnPropertyDescriptor(process, "resourcesPath");
  const handlers = {};
  const authorizationCalls = [];
  const pathAuthorizer = {
    authorize() {},
    authorizeIfExists(scope, targetPath, options) {
      authorizationCalls.push({ scope, targetPath, options });
      return null;
    },
    assertAuthorized(_scopes, targetPath) {
      return targetPath;
    },
    isAuthorized() {
      return true;
    },
  };

  Module._load = function (request, ...args) {
    if (request === "electron") {
      return {
        app: { getPath: () => tempDir },
        dialog: { showOpenDialog: async () => ({ canceled: true, filePaths: [] }) },
      };
    }
    return originalLoad.call(this, request, ...args);
  };
  Object.defineProperty(process, "resourcesPath", {
    configurable: true,
    value: tempDir,
  });

  try {
    const registerSigmaHandlers = require("../electron/ipc/sigma-handlers");
    registerSigmaHandlers(
      (channel, handler) => { handlers[channel] = handler; },
      () => {},
      {
        db: {},
        nextTabId: () => 1,
        _activeWindow: () => null,
        scheduleIndexBuild: () => {},
        jobManager: {},
        pathAuthorizer,
      },
    );
  } finally {
    Module._load = originalLoad;
    if (originalResourcesPath) {
      Object.defineProperty(process, "resourcesPath", originalResourcesPath);
    } else {
      delete process.resourcesPath;
    }
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  assert.equal(typeof handlers["sigma-scan"], "function");
  assert.equal(typeof handlers["sigma-scan-directory"], "function");
  assert.ok(
    authorizationCalls.length > 0,
    "registration should reuse the path authorizer supplied through the shared context",
  );
});
