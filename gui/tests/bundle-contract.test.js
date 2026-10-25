"use strict";
// Read-only checks. Does not launch or register the app.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { isDeepStrictEqual } = require("node:util");

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

test("local bundle's executables are built for the app's minimum macOS", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const bundle = path.join(root, "target/release/bundle/macos/Loose Keys.app");
  const minimum = execFileSync("/usr/bin/plutil", ["-extract", "LSMinimumSystemVersion", "raw", "-o", "-", path.join(root, "gui/macos/Info.plist")], { encoding: "utf8" }).trim();
  // Cargo reuses a release build made with another deployment target, so the
  // command could otherwise be bundled with a different minimum from the app's.
  for (const executable of ["loose-keys-gui", "loose-keys"]) {
    const build = execFileSync("/usr/bin/xcrun", ["vtool", "-show-build", path.join(bundle, "Contents/MacOS", executable)], { encoding: "utf8" });
    const found = [...build.matchAll(/^\s*minos\s+(\S+)$/gm)].map((m) => m[1]);
    assert.ok(found.length > 0, `${executable} records the macOS it was built for`);
    for (const minos of found) {
      assert.equal(minos, minimum, `${executable} is built for macOS ${minos}, not the app's minimum; check .cargo/config.toml, then run cargo clean --release once`);
    }
  }
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
    "Contents/Resources/en.lproj/Localizable.stringsdict",
    "Contents/Resources/es-419.lproj/Engine.strings",
    "Contents/Resources/es-419.lproj/InfoPlist.strings",
    "Contents/Resources/es-419.lproj/Localizable.strings",
    "Contents/Resources/es-419.lproj/Localizable.stringsdict",
    "Contents/Resources/es.lproj/Engine.strings",
    "Contents/Resources/es.lproj/InfoPlist.strings",
    "Contents/Resources/es.lproj/Localizable.strings",
    "Contents/Resources/es.lproj/Localizable.stringsdict",
    "Contents/_CodeSignature/CodeResources",
  ]);
});

test("local bundle names English as the language it is written in", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const plist = path.join(root, "target/release/bundle/macos/Loose Keys.app/Contents/Info.plist");
  const region = execFileSync("/usr/bin/plutil", ["-extract", "CFBundleDevelopmentRegion", "raw", "-o", "-", plist], { encoding: "utf8" }).trim();
  assert.equal(region, "en");
});

// The window's text tables. gui/build-macos.sh converts each source in
// gui/macos to a binary property list in the bundle. Engine.strings holds the
// engine's English as the window shows it; its keys are checked by a Rust test.

// Spanish values equal to their English that are right as they are, each with
// the reason. Anything else equal to its English has not been translated.
const UNTRANSLATED = new Set([
  // The panel's name: the same word in Spanish, as macOS's own apps use it.
  "Inspector",
  // The alert's button: Latin American macOS says OK where Spain's says Aceptar.
  "OK",
]);

const USAGE = ["NSDesktopFolderUsageDescription", "NSDocumentsFolderUsageDescription", "NSDownloadsFolderUsageDescription"];

// Integers the window shows that are not counts, each with the reason. Any
// other integer in a key is a count, which needs plural forms.
const NOT_COUNTS = new Set([
  // A line number.
  "%@, line %lld",
]);

// SwiftUI reads a localized Text as Markdown.
const MARKDOWN = ["*", "_", "`", "[", "]", "~"];

function table(file) {
  return JSON.parse(execFileSync("/usr/bin/plutil", ["-convert", "json", "-o", "-", file], { encoding: "utf8" }));
}

// A key as a .strings file writes it.
function literal(text) {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t")}"`;
}

function assertNone(problems, what) {
  assert.ok(problems.length === 0, `${what}:\n${problems.join("\n")}`);
}

// Every key the window and the notification look up, with its English: the
// default value when the code gives one, otherwise the key. The window's keys
// are the ones swiftc wrote to target/release/strings during the build.
function lookedUp(root) {
  const folder = path.join(root, "target/release/strings");
  const files = fs.existsSync(folder) ? fs.readdirSync(folder).filter((name) => name.endsWith(".stringsdata")).sort() : [];
  assert.ok(files.length > 0, `No .stringsdata files in ${folder}: run sh gui/build-macos.sh first`);
  const english = new Map();
  const problems = [];
  const add = (key, text, where) => {
    if (english.has(key) && english.get(key) !== text) {
      problems.push(`${where}: ${literal(key)} has two English texts, ${literal(english.get(key))} and ${literal(text)}`);
    }
    english.set(key, text);
  };
  for (const name of files) {
    const data = JSON.parse(fs.readFileSync(path.join(folder, name), "utf8"));
    for (const [tableName, entries] of Object.entries(data.tables)) {
      if (tableName !== "Localizable") {
        problems.push(`${data.source} looks up table ${tableName}; only Localizable is checked for its Spanish`);
        continue;
      }
      for (const entry of entries) {
        add(entry.key, entry.value ?? entry.key, data.source);
      }
    }
  }
  const notifications = notificationKeys(fs.readFileSync(path.join(root, "gui/src/notifications.m"), "utf8"));
  problems.push(...notifications.problems);
  for (const key of notifications.keys) {
    add(key, key, "gui/src/notifications.m");
  }
  return { english, problems };
}

// Each NSLocalizedString key, which must be one string literal with no
// escapes and then the comma: the compiler joins adjacent literals, and a key
// read only in part, or with its escapes as written, would be checked in place
// of the real one.
function notificationKeys(source) {
  const calls = source.match(/NSLocalizedString\s*\(/g) ?? [];
  const keys = [...source.matchAll(/NSLocalizedString\s*\(\s*@"([^"\\\n]*)"\s*,/g)].map((m) => m[1]);
  return { keys, problems: keys.length === calls.length ? [] : ["gui/src/notifications.m: an NSLocalizedString key is not one plain string literal, without escapes"] };
}

// Keys the window looks up that Spanish lacks, Spanish keys it no longer looks
// up, and keys in both Spanish files.
function completeness(english, strings, plurals) {
  const have = new Set([...Object.keys(strings), ...Object.keys(plurals)]);
  return {
    missing: [...english.keys()].filter((key) => !have.has(key)).sort(),
    stale: [...have].filter((key) => !english.has(key)).sort(),
    both: Object.keys(strings).filter((key) => Object.hasOwn(plurals, key)).sort(),
  };
}

// Keys with a count that have no plural forms. English takes its plural forms
// only from en.lproj/Localizable.stringsdict, so a count anywhere else would
// show "1 places".
function countsWithoutPlurals(english, plurals) {
  return [...english.keys()].filter((key) => /%(?:[1-9]\d*\$)?(?:ll?)?[du]/.test(key) && !NOT_COUNTS.has(key) && !Object.hasOwn(plurals, key)).sort();
}

// A format specifier: an optional position, then flags, width and precision,
// which take no argument, then the length and conversion that give the
// argument's type. %#@name@ is a stringsdict variable.
const SPECIFIER = /%(?:([1-9]\d*)\$)?(?:#@(\w+)@|[-+ #0]*\d*(?:\.\d+)?((?:hh|h|ll|l|q|z|t|j|L)?[@dDiuUxXoOfFeEgGaAcCsSp]|%))/y;

// A format's specifiers as written, each with its position if it has one, and
// its count of %%. variables gives a stringsdict variable's value type.
function specifiers(text, variables = {}) {
  const found = [];
  const problems = [];
  let percents = 0;
  for (let at = text.indexOf("%"); at !== -1; at = text.indexOf("%", at)) {
    SPECIFIER.lastIndex = at;
    const match = SPECIFIER.exec(text);
    if (!match) {
      problems.push(`has a % that is not a format specifier: ${literal(text.slice(at, at + 4))}`);
      at += 1;
      continue;
    }
    at = SPECIFIER.lastIndex;
    const [, position, variable, type] = match;
    if (type === "%") {
      percents += 1;
    } else if (variable === undefined) {
      found.push({ position, type });
    } else if (Object.hasOwn(variables, variable)) {
      found.push({ position, type: variables[variable] });
    } else {
      problems.push(`has %#@${variable}@, which is not a plural rule here`);
    }
  }
  return { found, percents, problems };
}

// The argument types a format takes, in argument order, and its count of %%.
function formatArguments(text, variables = {}) {
  const { found, percents, problems } = specifiers(text, variables);
  const numbered = found.filter((f) => f.position !== undefined);
  if (numbered.length === 0) {
    return { types: found.map((f) => f.type), percents, problems };
  }
  if (numbered.length < found.length) {
    problems.push("mixes numbered and unnumbered specifiers");
  }
  const types = [];
  for (const { position, type } of numbered) {
    if (types[position - 1] !== undefined && types[position - 1] !== type) {
      problems.push(`uses argument ${position} as two types`);
    }
    types[position - 1] = type;
  }
  for (let i = 0; i < types.length; i++) {
    if (types[i] === undefined) {
      problems.push(`skips argument ${i + 1}`);
      types[i] = "?";
    }
  }
  return { types, percents, problems };
}

// A translation must take the arguments its English takes, of the same types,
// or formatting it reads the wrong argument.
function formatProblems(english, translated, variables = {}) {
  const want = formatArguments(english);
  const got = formatArguments(translated, variables);
  const problems = [...want.problems.map((p) => `its English ${p}`), ...got.problems];
  const show = (types) => types.map((type) => `%${type}`).join(" ") || "no arguments";
  if (show(want.types) !== show(got.types)) {
    problems.push(`takes ${show(got.types)}, but its English takes ${show(want.types)}`);
  }
  if (want.percents !== got.percents) {
    problems.push(`has ${got.percents} %%, but its English has ${want.percents}`);
  }
  return problems;
}

// A stringsdict entry: its format must take the arguments its English takes,
// each %#@variable@ being a plural rule with at least the forms "one" and
// "other", every form showing its number once, unnumbered or with the
// variable's own position, as Foundation formats both.
function pluralProblems(english, entry) {
  const format = entry?.NSStringLocalizedFormatKey;
  if (typeof format !== "string") {
    return ["has no NSStringLocalizedFormatKey"];
  }
  const problems = [];
  const variables = {};
  for (const [, position, name] of format.matchAll(/%(?:([1-9]\d*)\$)?#@(\w+)@/g)) {
    const rule = entry[name];
    const type = rule?.NSStringFormatValueTypeKey;
    if (rule?.NSStringFormatSpecTypeKey !== "NSStringPluralRuleType") {
      problems.push(`${name}: NSStringFormatSpecTypeKey is not NSStringPluralRuleType`);
      continue;
    }
    if (typeof type !== "string" || formatArguments(`%${type}`).types.join() !== type) {
      problems.push(`${name}: NSStringFormatValueTypeKey is not a format type`);
      continue;
    }
    variables[name] = type;
    for (const form of ["one", "other"]) {
      if (!Object.hasOwn(rule, form)) {
        problems.push(`${name}: has no "${form}" form`);
      }
    }
    for (const [form, text] of Object.entries(rule)) {
      if (form.startsWith("NSString")) {
        continue;
      }
      if (typeof text !== "string") {
        problems.push(`${name}.${form}: is not text`);
        continue;
      }
      const args = specifiers(text);
      problems.push(...args.problems.map((p) => `${name}.${form}: ${p}`));
      const [shown] = args.found;
      if (args.found.length !== 1 || shown.type !== type || (shown.position ?? position) !== position) {
        problems.push(`${name}.${form}: must show its number once, as %${type}${position ? ` or %${position}$${type}` : ""}, and take nothing else`);
      }
    }
  }
  problems.push(...formatProblems(english, format, variables));
  return problems;
}

// Every text a stringsdict entry can show, with its variables left out.
function pluralTexts(entry) {
  const texts = [entry.NSStringLocalizedFormatKey.replace(/%(?:[1-9]\d*\$)?#@\w+@/g, "")];
  for (const rule of Object.values(entry)) {
    if (rule !== null && typeof rule === "object") {
      texts.push(...Object.entries(rule).filter(([form, text]) => !form.startsWith("NSString") && typeof text === "string").map(([, text]) => text));
    }
  }
  return texts;
}

// A translation may use only the Markdown characters its English uses.
function markdownProblems(english, translated) {
  return MARKDOWN.filter((c) => translated.includes(c) && !english.includes(c)).map((c) => `has ${c}, which its English does not; SwiftUI reads it as Markdown`);
}

// Keys whose value is still its English.
function untranslated(values, englishOf) {
  return Object.keys(values).filter((key) => !UNTRANSLATED.has(key) && isDeepStrictEqual(values[key], englishOf(key))).sort();
}

// An es-419 entry replaces an es one; one that is not in es, or that says the
// same, is a mistake.
function overrideProblems(base, override) {
  return Object.keys(override).sort().flatMap((key) => {
    if (!Object.hasOwn(base, key)) {
      return [`${literal(key)} is not in es.lproj`];
    }
    return override[key] === base[key] ? [`${literal(key)} says the same as es.lproj`] : [];
  });
}

// A .strings file's entries as its text has them, repeats included, read the
// way plutil reads them: comments, then a key, an optional = and value, and a
// semicolon. Each entry gives its key, its line, and whether it is a line of
// its own that starts with its quoted key.
function stringsEntries(text) {
  const entries = [];
  const problems = [];
  const lineAt = (i) => text.slice(0, i).split("\n").length;
  const GAP = /(?:\s+|\/\*[\s\S]*?\*\/|\/\/[^\n]*)*/y;
  const TOKEN = /"((?:[^"\\]|\\[\s\S])*)"|([\w$+/:.-]+)/y;
  let at = 0;
  const skip = () => {
    GAP.lastIndex = at;
    GAP.exec(text);
    at = GAP.lastIndex;
  };
  const token = () => {
    TOKEN.lastIndex = at;
    const match = TOKEN.exec(text);
    if (match) {
      at = TOKEN.lastIndex;
    }
    return match && (match[2] ?? unescapeStrings(match[1]));
  };
  for (skip(); at < text.length; skip()) {
    const start = at;
    const key = token();
    skip();
    if (key !== null && text[at] === "=") {
      at += 1;
      skip();
      if (token() === null) {
        problems.push(`line ${lineAt(at)}: has no value after its =`);
        break;
      }
      skip();
    }
    if (key === null || text[at] !== ";") {
      problems.push(`line ${lineAt(at)}: is not a "key" = "value"; entry as plutil reads one`);
      break;
    }
    at += 1;
    const end = text.indexOf("\n", at);
    const own = (start === 0 || text[start - 1] === "\n") && text[start] === '"' && !text.slice(start, at).includes("\n") && /^[ \t\r]*$/.test(text.slice(at, end === -1 ? text.length : end));
    entries.push({ key, line: lineAt(start), own });
  }
  return { entries, problems };
}

// A quoted .strings text as plutil decodes it: \U and up to four hex digits,
// up to three octal digits, a C letter escape, or the character itself.
function unescapeStrings(text) {
  return text.replace(/\\(?:U([0-9A-Fa-f]{1,4})|([0-7]{1,3})|([\s\S]))/g, (_, hex, octal, c) => {
    if (hex !== undefined) {
      return String.fromCharCode(parseInt(hex, 16));
    }
    if (octal !== undefined) {
      return String.fromCharCode(parseInt(octal, 8));
    }
    return { a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v" }[c] ?? c;
  });
}

// plutil keeps the last of two entries with one key and says nothing, so
// repeats are found in the text, and every entry is kept to a line of its own
// so the file reads as plutil reads it. keys are the ones plutil read.
function repeatProblems(text, keys) {
  const { entries, problems } = stringsEntries(text);
  const seen = new Set();
  const repeated = new Set();
  for (const { key } of entries) {
    (seen.has(key) ? repeated : seen).add(key);
  }
  return [
    ...problems,
    ...entries.filter((entry) => !entry.own).map(({ key, line }) => `line ${line}: ${literal(key)} is not on a line of its own that starts with its quoted key`),
    ...[...repeated].map((key) => `${literal(key)} is there more than once; only the last counts`),
    ...keys.filter((key) => !seen.has(key)).map((key) => `${literal(key)} is read by plutil but not by this check`),
    ...[...seen].filter((key) => !keys.includes(key)).map((key) => `${literal(key)} is not read by plutil as written`),
  ];
}

test("local bundle carries each language's tables, built from their sources", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const resources = path.join(root, "target/release/bundle/macos/Loose Keys.app/Contents/Resources");
  const source = (name) => table(path.join(root, "gui/macos", name));
  const expected = {
    "en.lproj/Localizable.stringsdict": source("en.lproj/Localizable.stringsdict"),
    "es.lproj/Engine.strings": source("es.lproj/Engine.strings"),
    "es.lproj/InfoPlist.strings": source("es.lproj/InfoPlist.strings"),
    "es.lproj/Localizable.strings": source("es.lproj/Localizable.strings"),
    "es.lproj/Localizable.stringsdict": source("es.lproj/Localizable.stringsdict"),
    // macOS does not look in es.lproj for a key es-419.lproj lacks.
    "es-419.lproj/Engine.strings": { ...source("es.lproj/Engine.strings"), ...source("es-419.lproj/Engine.strings") },
    "es-419.lproj/Localizable.strings": { ...source("es.lproj/Localizable.strings"), ...source("es-419.lproj/Localizable.strings") },
    "es-419.lproj/InfoPlist.strings": source("es.lproj/InfoPlist.strings"),
    "es-419.lproj/Localizable.stringsdict": source("es.lproj/Localizable.stringsdict"),
  };
  for (const [name, contents] of Object.entries(expected)) {
    const file = path.join(resources, name);
    assert.equal(fs.readFileSync(file).subarray(0, 8).toString("latin1"), "bplist00", `${name} is a binary property list`);
    assert.deepEqual(table(file), contents, `${name} is built from its source`);
  }
});

test("gui/macos holds only the tables the build puts in the bundle", { skip: process.platform !== "darwin" }, () => {
  const macos = path.join(path.resolve(__dirname, "../.."), "gui/macos");
  // gui/build-macos.sh converts these files by name, and gives es-419.lproj
  // the other two from es.lproj, so any other table would be left out.
  const files = fs
    .readdirSync(macos, { recursive: true })
    .filter((name) => path.basename(name) !== ".DS_Store" && fs.lstatSync(path.join(macos, name)).isFile())
    .filter((name) => /\.lproj(\/|$)/.test(name) || /\.strings(dict)?$/.test(name))
    .sort();
  assert.deepEqual(files, [
    "en.lproj/Localizable.stringsdict",
    "es-419.lproj/Engine.strings",
    "es-419.lproj/Localizable.strings",
    "es.lproj/Engine.strings",
    "es.lproj/InfoPlist.strings",
    "es.lproj/Localizable.strings",
    "es.lproj/Localizable.stringsdict",
  ]);
});

test("every key the window looks up has its Spanish", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const { english, problems } = lookedUp(root);
  const strings = table(path.join(root, "gui/macos/es.lproj/Localizable.strings"));
  const plurals = table(path.join(root, "gui/macos/es.lproj/Localizable.stringsdict"));
  const englishPlurals = table(path.join(root, "gui/macos/en.lproj/Localizable.stringsdict"));
  const { missing, stale, both } = completeness(english, strings, plurals);
  const list = (heading, keys, line = literal) => (keys.length === 0 ? [] : [`${heading} (${keys.length}):`, ...keys.map(line)]);
  problems.push(
    ...list("Missing from es.lproj/Localizable.strings", missing.filter((key) => !Object.hasOwn(englishPlurals, key)), (key) => `${literal(key)} = "";`),
    ...list("Missing from es.lproj/Localizable.stringsdict, where en.lproj has its plural forms", missing.filter((key) => Object.hasOwn(englishPlurals, key))),
    ...list("Stale in es.lproj, looked up by nothing", stale),
    ...list("In both es.lproj/Localizable.strings and es.lproj/Localizable.stringsdict", both),
    ...list("In en.lproj/Localizable.stringsdict but not es.lproj's", Object.keys(englishPlurals).filter((key) => !Object.hasOwn(plurals, key)).sort()),
    ...list("In es.lproj/Localizable.stringsdict but not en.lproj's", Object.keys(plurals).filter((key) => !Object.hasOwn(englishPlurals, key)).sort()),
    ...list("Counts not in es.lproj/Localizable.stringsdict and en.lproj's, so English would show \"1 places\" (if one is not a count, add it to NOT_COUNTS with why)", countsWithoutPlurals(english, plurals)),
  );
  assertNone(problems, "The Spanish tables do not match what the window looks up");
});

test("Spanish text takes the arguments its English takes and adds no Markdown", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const { english } = lookedUp(root);
  const problems = [];
  for (const name of ["es.lproj/Localizable.strings", "es-419.lproj/Localizable.strings"]) {
    for (const [key, value] of Object.entries(table(path.join(root, "gui/macos", name)))) {
      const source = english.get(key) ?? key;
      problems.push(...[...formatProblems(source, value), ...markdownProblems(source, value)].map((p) => `${name} ${literal(key)}: ${p}`));
    }
  }
  for (const name of ["en.lproj/Localizable.stringsdict", "es.lproj/Localizable.stringsdict"]) {
    for (const [key, entry] of Object.entries(table(path.join(root, "gui/macos", name)))) {
      const source = english.get(key) ?? key;
      const found = pluralProblems(source, entry);
      if (found.length === 0 && name.startsWith("es.")) {
        found.push(...pluralTexts(entry).flatMap((text) => markdownProblems(source, text)));
      }
      problems.push(...found.map((p) => `${name} ${literal(key)}: ${p}`));
    }
  }
  assertNone(problems, "Spanish text that would show the wrong thing");
});

test("Spanish text is translated", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const { english } = lookedUp(root);
  const englishPlurals = table(path.join(root, "gui/macos/en.lproj/Localizable.stringsdict"));
  const problems = [];
  for (const name of ["es.lproj/Localizable.strings", "es-419.lproj/Localizable.strings"]) {
    const values = table(path.join(root, "gui/macos", name));
    problems.push(...untranslated(values, (key) => english.get(key) ?? key).map((key) => `${name} ${literal(key)}`));
  }
  const plurals = table(path.join(root, "gui/macos/es.lproj/Localizable.stringsdict"));
  problems.push(...untranslated(plurals, (key) => englishPlurals[key]).map((key) => `es.lproj/Localizable.stringsdict ${literal(key)}`));
  assertNone(problems, "Spanish values that are still the English (if one is right, add it to UNTRANSLATED with why)");
});

test("folder-access reasons have their Spanish", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const strings = table(path.join(root, "gui/macos/es.lproj/InfoPlist.strings"));
  const info = table(path.join(root, "gui/macos/Info.plist"));
  assert.deepEqual(Object.keys(strings).sort(), USAGE, "es.lproj/InfoPlist.strings holds exactly the folder-access reasons");
  for (const key of USAGE) {
    assert.ok(Object.hasOwn(info, key), `Info.plist has no ${key}`);
    assert.notEqual(strings[key], info[key], `es.lproj/InfoPlist.strings ${literal(key)} is the English`);
  }
});

test("Latin American Spanish changes only what differs from Spain's", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  for (const name of ["Engine.strings", "Localizable.strings"]) {
    const base = table(path.join(root, "gui/macos/es.lproj", name));
    assertNone(overrideProblems(base, table(path.join(root, "gui/macos/es-419.lproj", name))), `es-419.lproj/${name}`);
  }
});

test("no table has two entries with one key", { skip: process.platform !== "darwin" }, () => {
  const root = path.resolve(__dirname, "../..");
  const macos = path.join(root, "gui/macos");
  const files = fs.readdirSync(macos, { recursive: true }).filter((name) => name.endsWith(".strings")).sort();
  assert.ok(files.length > 0, `No .strings files in ${macos}`);
  for (const name of files) {
    const file = path.join(macos, name);
    assertNone(repeatProblems(fs.readFileSync(file, "utf8"), Object.keys(table(file))), name);
  }
});

test("table checks catch what they are for", () => {
  const english = new Map([
    ["Scan Now", "Scan Now"],
    ["%lld places were not read", "%lld places were not read"],
  ]);
  assert.deepEqual(completeness(english, { "Scan Now": "Analizar ahora", Old: "Antiguo" }, {}), {
    missing: ["%lld places were not read"],
    stale: ["Old"],
    both: [],
  });
  assert.deepEqual(completeness(english, { "Scan Now": "Analizar", "%lld places were not read": "x" }, { "%lld places were not read": {} }).both, [
    "%lld places were not read",
  ]);
  // A count kept in Localizable.strings has no plural forms; a line number needs none.
  assert.deepEqual(countsWithoutPlurals(new Map([...english, ["%@, line %lld", "%@, line %lld"], ["%2$lu of %1$@", "%2$lu of %1$@"]]), {}), [
    "%2$lu of %1$@",
    "%lld places were not read",
  ]);
  const notLiteral = ["gui/src/notifications.m: an NSLocalizedString key is not one plain string literal, without escapes"];
  assert.deepEqual(notificationKeys('NSLocalizedString(@"Review", @"c");'), { keys: ["Review"], problems: [] });
  assert.deepEqual(notificationKeys('NSLocalizedString(@"a" @"b", @"c");'), { keys: [], problems: notLiteral });
  assert.deepEqual(notificationKeys('NSLocalizedString(@"a\\"b", @"c");\nNSLocalizedString(key, @"c");'), { keys: [], problems: notLiteral });

  assert.deepEqual(formatProblems("Scanned %@ of %lld.", "Analizado %2$lld de %1$@."), []);
  assert.deepEqual(formatProblems("Scanned %@ of %lld.", "Analizado %lld de %@."), ["takes %lld %@, but its English takes %@ %lld"]);
  assert.deepEqual(formatProblems("Scanned %@.", "Analizado."), ["takes no arguments, but its English takes %@"]);
  assert.deepEqual(formatProblems("%lld found", "%d encontrados"), ["takes %d, but its English takes %lld"]);
  assert.deepEqual(formatProblems("100%% done", "100 % hecho"), ["takes %he, but its English takes no arguments", "has 0 %%, but its English has 1"]);
  assert.deepEqual(formatProblems("%@ and %@", "%1$@ y %3$@"), ["skips argument 2", "takes %@ %? %@, but its English takes %@ %@"]);
  assert.ok(formatProblems("Done", "Hecho al 50%").length > 0);

  const rule = (one, other, type = "lld") => ({
    NSStringLocalizedFormatKey: "%#@places@ were not read",
    places: { NSStringFormatSpecTypeKey: "NSStringPluralRuleType", NSStringFormatValueTypeKey: type, one, other },
  });
  assert.deepEqual(pluralProblems("%lld places were not read", rule("%lld place", "%lld places")), []);
  assert.deepEqual(pluralProblems("%lld places were not read", { NSStringLocalizedFormatKey: "%#@places@ were not read", places: { NSStringFormatSpecTypeKey: "NSStringPluralRuleType", NSStringFormatValueTypeKey: "lld", other: "%lld places" } }), [
    'places: has no "one" form',
  ]);
  assert.deepEqual(pluralProblems("%lld places were not read", rule("one place", "%lld places")), ["places.one: must show its number once, as %lld, and take nothing else"]);
  const two = (items, found) => ({
    NSStringLocalizedFormatKey: "%2$#@found@ de %1$#@items@.",
    items: { NSStringFormatSpecTypeKey: "NSStringPluralRuleType", NSStringFormatValueTypeKey: "lld", one: items, other: items },
    found: { NSStringFormatSpecTypeKey: "NSStringPluralRuleType", NSStringFormatValueTypeKey: "lld", one: found, other: found },
  });
  assert.deepEqual(pluralProblems("%lld items looked at, %lld found.", two("%1$lld vistos", "%2$lld hallados")), []);
  assert.deepEqual(pluralProblems("%lld items looked at, %lld found.", two("%lld vistos", "%lld hallados")), []);
  assert.deepEqual(pluralProblems("%lld items looked at, %lld found.", two("%1$lld vistos", "%1$lld hallados")), [
    "found.one: must show its number once, as %lld or %2$lld, and take nothing else",
    "found.other: must show its number once, as %lld or %2$lld, and take nothing else",
  ]);
  assert.deepEqual(pluralProblems("%lld places were not read", rule("%@ place", "%@ places", "@")), ["takes %@, but its English takes %lld"]);
  assert.deepEqual(pluralProblems("%lld places were not read", {}), ["has no NSStringLocalizedFormatKey"]);

  assert.deepEqual(markdownProblems("Open the file", "Abre el *archivo*"), ["has *, which its English does not; SwiftUI reads it as Markdown"]);
  assert.deepEqual(markdownProblems("Run `ssh-add`", "Ejecuta `ssh-add`"), []);
  assert.deepEqual(pluralTexts({ NSStringLocalizedFormatKey: "%#@file_count@", file_count: { NSStringFormatSpecTypeKey: "NSStringPluralRuleType", one: "_a_", other: "b" } }), ["", "_a_", "b"]);

  assert.deepEqual(untranslated({ "Scan Now": "Scan Now", Status: "Estado" }, (key) => key), ["Scan Now"]);
  assert.deepEqual(untranslated({ k: { a: "x" } }, () => ({ a: "x" })), ["k"]);

  assert.deepEqual(overrideProblems({ a: "computadora", b: "ordenador" }, { a: "computadora", b: "computadora", c: "x" }), [
    '"a" says the same as es.lproj',
    '"c" is not in es.lproj',
  ]);

  const text = '/* "b" = "in a comment";\n   "b" = "still";\n*/\n"a" = "1";\n"say \\"hi\\" \\U00e9" = "2";\n"a" = "3";\n/* x */ "c" = "4";\n';
  assert.deepEqual(
    stringsEntries(text).entries.map(({ key }) => key),
    ["a", 'say "hi" é', "a", "c"],
  );
  assert.deepEqual(repeatProblems(text, ["a", 'say "hi" é', "c"]), [
    'line 7: "c" is not on a line of its own that starts with its quoted key',
    '"a" is there more than once; only the last counts',
  ]);
  assert.deepEqual(repeatProblems('/* c */\n"Cancel" = "Cancelar";\n"Scan Now" = "Analizar ahora";\n  "Cancel" = "Anular";\n', ["Cancel", "Scan Now"]), [
    'line 4: "Cancel" is not on a line of its own that starts with its quoted key',
    '"Cancel" is there more than once; only the last counts',
  ]);
  assert.deepEqual(repeatProblems('"Scan Now" = "Analizar";\n"Cancel" = "Cancelar"; "Scan Now" = "Scan Now";\n', ["Scan Now", "Cancel"]), [
    'line 2: "Cancel" is not on a line of its own that starts with its quoted key',
    'line 2: "Scan Now" is not on a line of its own that starts with its quoted key',
    '"Scan Now" is there more than once; only the last counts',
  ]);
  assert.deepEqual(repeatProblems('"a" = "1";\n"b" =\n  "2";\n', ["a", "b"]), ['line 2: "b" is not on a line of its own that starts with its quoted key']);
  assert.deepEqual(repeatProblems('"a" = "1"\n"b" = "2";\n', []), ['line 2: is not a "key" = "value"; entry as plutil reads one']);
  assert.deepEqual(repeatProblems('"a" = "1";\n', ["a", "b"]), ['"b" is read by plutil but not by this check']);
});
