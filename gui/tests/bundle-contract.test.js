"use strict";
// Read-only checks. Does not launch or register the app.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

test("local bundle has a sealed plist and matching notification identity", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const bundle = path.join(root, "target/release/bundle/macos/Loose Keys.app");
  const source = path.join(root, "gui/macos/Info.plist");
  const plist = path.join(bundle, "Contents/Info.plist");
  assert.deepEqual(fs.readFileSync(plist), fs.readFileSync(source));
  const minimum = execFileSync("/usr/bin/plutil", ["-extract", "LSMinimumSystemVersion", "raw", "-o", "-", plist], { encoding: "utf8" }).trim();
  assert.equal(minimum, "14.0");
  execFileSync("/usr/bin/plutil", ["-lint", plist]);
  const identifier = execFileSync("/usr/bin/plutil", ["-extract", "CFBundleIdentifier", "raw", "-o", "-", source], { encoding: "utf8" }).trim();
  execFileSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", `-R=identifier "${identifier}"`, bundle]);
});

test("local bundle carries the background agent's launchd job", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const bundle = path.join(root, "target/release/bundle/macos/Loose Keys.app");
  const job = path.join(bundle, "Contents/Library/LaunchAgents/dev.loosekeys.agent.plist");
  assert.deepEqual(fs.readFileSync(job), fs.readFileSync(path.join(root, "gui/macos/dev.loosekeys.agent.plist")));
  execFileSync("/usr/bin/plutil", ["-lint", job]);
  const value = (key) => execFileSync("/usr/bin/plutil", ["-extract", key, "raw", "-o", "-", job], { encoding: "utf8" }).trim();
  // The job runs this bundle's own executable, headless, at background priority.
  const executable = execFileSync("/usr/bin/plutil", ["-extract", "CFBundleExecutable", "raw", "-o", "-", path.join(bundle, "Contents/Info.plist")], { encoding: "utf8" }).trim();
  assert.equal(value("BundleProgram"), `Contents/MacOS/${executable}`);
  assert.ok(fs.existsSync(path.join(bundle, value("BundleProgram"))));
  assert.equal(value("ProgramArguments.1"), "--agent");
  assert.equal(value("ProcessType"), "Background");
  assert.equal(value("LowPriorityIO"), "true");
  assert.equal(value("KeepAlive.SuccessfulExit"), "false");
});

test("local bundle carries the loose-keys command, signed inside it", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const bundle = path.join(root, "target/release/bundle/macos/Loose Keys.app");
  const command = path.join(bundle, "Contents/MacOS/loose-keys");
  const identifier = execFileSync("/usr/bin/plutil", ["-extract", "CFBundleIdentifier", "raw", "-o", "-", path.join(root, "gui/macos/Info.plist")], { encoding: "utf8" }).trim();
  execFileSync("/usr/bin/codesign", ["--verify", "--strict", `-R=identifier "${identifier}.cli"`, command]);
  // --version reads no files, so this runs nothing against the home folder.
  assert.match(execFileSync(command, ["--version"], { encoding: "utf8" }), /^loose-keys \d+\.\d+\.\d+\n$/);
});

test("local bundle holds only what the build makes", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const bundle = path.join(root, "target/release/bundle/macos/Loose Keys.app");
  // A file left by an earlier build would otherwise be sealed into the signature.
  const files = fs.readdirSync(bundle, { recursive: true }).filter((name) => fs.lstatSync(path.join(bundle, name)).isFile()).sort();
  assert.deepEqual(files, [
    "Contents/Info.plist",
    "Contents/Library/LaunchAgents/dev.loosekeys.agent.plist",
    "Contents/MacOS/loose-keys",
    "Contents/MacOS/loose-keys-gui",
    "Contents/Resources/AppIcon.icns",
    "Contents/_CodeSignature/CodeResources",
  ]);
});
