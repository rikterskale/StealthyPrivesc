// StealthyPrivesc JScript fallback (cscript) — authorized assessments only.
// Quiet-leaning WMI / WScript enumeration. No exploitation.

var wsh = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var authorized = false;
var wantJson = false;
var coverageErrors = {};
for (var a = 0; a < WScript.Arguments.length; a++) {
  var arg = String(WScript.Arguments.Item(a)).toLowerCase();
  if (arg === "--authorized" || arg === "--i-understand-authorized-use-only") {
    authorized = true;
  }
  if (arg === "--json") {
    wantJson = true;
  }
}
if (wsh.ExpandEnvironmentStrings("%STEALTHY_AUTHORIZED%") === "1") {
  authorized = true;
}
if (!authorized) {
  WScript.Echo("Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1");
  WScript.Quit(2);
}

function envOr(name, fallback) {
  var value = wsh.ExpandEnvironmentStrings("%" + name + "%");
  if (!value || value === "%" + name + "%") {
    return fallback;
  }
  return value;
}

function jsonEscape(value) {
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
}

function recordCoverageError(plugin, source, error) {
  if (!coverageErrors[plugin]) {
    coverageErrors[plugin] = [];
  }
  if (coverageErrors[plugin].length >= 8) {
    return;
  }
  var code = "";
  if (error && typeof error.number !== "undefined") {
    code = " (error " + error.number + ")";
  }
  coverageErrors[plugin].push(source + " unreadable" + code);
}

function isMissingRegistryValue(error) {
  if (!error || typeof error.number === "undefined") {
    return false;
  }
  var code = error.number >>> 0;
  return code === 2147942402 || code === 2147942403;
}

function readAie(root) {
  try {
    var key = root + "\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
    return wsh.RegRead(key + "\\AlwaysInstallElevated");
  } catch (e) {
    if (!isMissingRegistryValue(e)) {
      recordCoverageError(
        "windows.always_install_elevated",
        root + " AlwaysInstallElevated",
        e
      );
    }
    return null;
  }
}

function collectFindings() {
  var findings = [];
  var hklm = readAie("HKLM");
  var hkcu = readAie("HKCU");
  if (hklm === 1 && hkcu === 1) {
    findings.push({
      plugin: "windows.always_install_elevated",
      kind: "misconfiguration",
      severity: "high",
      title: "AlwaysInstallElevated fully enabled",
      detail: "HKLM and HKCU AlwaysInstallElevated are both 1",
      recommendation: "Disable AlwaysInstallElevated in both hives.",
      noisy: false,
      leaves_artifacts: false,
      object: "HKLM+HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated",
      condition: "always-install-elevated-fully-enabled"
    });
  }

  var paths = [
    "C:\\Windows\\Panther\\Unattend.xml",
    "C:\\Windows\\Panther\\unattend.xml",
    "C:\\Windows\\System32\\sysprep\\unattend.xml",
    "C:\\Windows\\System32\\config\\RegBack\\SAM"
  ];
  for (var i = 0; i < paths.length; i++) {
    if (fso.FileExists(paths[i])) {
      findings.push({
        plugin: "windows.credentials",
        kind: "credential",
        severity: "medium",
        title: "Sensitive file present",
        detail: paths[i],
        recommendation: "Inspect and restrict access; remove stale unattend/SAM backups.",
        noisy: false,
        leaves_artifacts: false,
        object: paths[i],
        condition: "sensitive-file-present"
      });
    }
  }

  var applocker = [];
  var names = ["Exe", "Script", "Msi", "Dll", "Appx"];
  for (var n = 0; n < names.length; n++) {
    try {
      wsh.RegRead(
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\" +
          names[n] +
          "\\EnforcementMode"
      );
      applocker.push(names[n]);
    } catch (e) {
      if (!isMissingRegistryValue(e)) {
        recordCoverageError(
          "windows.endpoint_controls",
          "AppLocker " + names[n] + " EnforcementMode",
          e
        );
      }
    }
  }
  if (applocker.length > 0) {
    findings.push({
      plugin: "windows.endpoint_controls",
      kind: "enumeration",
      severity: "info",
      title: "AppLocker SrpV2 EnforcementMode readable",
      detail: applocker.join(","),
      recommendation: "If custom PE is blocked, use approved script hosts.",
      noisy: false,
      leaves_artifacts: false,
      object: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2",
      condition: "applocker-enforcement-mode-readable"
    });
  }

  try {
    var vbs = wsh.RegRead(
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity"
    );
    if (vbs === 1) {
      findings.push({
        plugin: "windows.endpoint_controls",
        kind: "enumeration",
        severity: "info",
        title: "VBS enabled",
        detail: "EnableVirtualizationBasedSecurity=1",
        recommendation: "WDAC/CI stack may be active; prefer allowlisted hosts.",
        noisy: false,
        leaves_artifacts: false,
        object: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity",
        condition: "virtualization-based-security-enabled"
      });
    }
  } catch (e) {
    if (!isMissingRegistryValue(e)) {
      recordCoverageError(
        "windows.endpoint_controls",
        "DeviceGuard EnableVirtualizationBasedSecurity",
        e
      );
    }
  }

  return findings;
}

function emitJson(findings) {
  var runId = (new Date().getTime().toString(16) + Math.floor(Math.random() * 1e8).toString(16)).substring(0, 24);
  var started = Math.floor(new Date().getTime() / 1000);
  var executionPath = envOr("STEALTHY_EXECUTION_PATH", "script");
  var primaryLaunch = envOr("STEALTHY_PRIMARY_LAUNCH", "not_applicable");
  var roeRef = envOr("STEALTHY_MANIFEST_ROE_REF", "");
  // Honest delta: JScript covers a thin subset versus native plugins.
  var delta = [
    "windows.services",
    "windows.scheduled_tasks",
    "windows.uac",
    "windows.dll_hijack",
    "windows.admin_sessions",
    "windows.env_path",
    "windows.autoruns",
    "windows.app_control",
    "windows.privileges"
  ];
  var collected = [
    "windows.always_install_elevated",
    "windows.credentials",
    "windows.endpoint_controls"
  ];
  var out = [];
  out.push("{");
  out.push('"schema_version":"2",');
  out.push('"run_id":"' + jsonEscape(runId) + '",');
  out.push('"started_at_unix":' + started + ",");
  out.push('"tool":"stealthy-script",');
  out.push('"version":"0.1.0",');
  out.push('"authorized_use_ack":true,');
  out.push('"mode":"enumerate-only",');
  out.push('"execution_path":"' + jsonEscape(executionPath) + '",');
  out.push('"primary_launch":"' + jsonEscape(primaryLaunch) + '",');
  out.push('"roe_ref":"' + jsonEscape(roeRef) + '",');
  out.push('"profile":"script",');
  out.push('"coverage_mode":"script",');
  out.push('"capability_delta":[');
  for (var d = 0; d < delta.length; d++) {
    out.push('"' + delta[d] + '"' + (d + 1 < delta.length ? "," : ""));
  }
  out.push("],");
  out.push(
    '"os":{"family":"windows","os":"windows","arch":"' +
      jsonEscape(envOr("PROCESSOR_ARCHITECTURE", "unknown")) +
      '","version_hint":""},'
  );
  out.push(
    '"identity":{"username":"' +
      jsonEscape(envOr("USERNAME", "")) +
      '","uid":null,"gid":null,"groups":[],"is_elevated":false,"elevation_source":"jscript","token_context":"","hostname":"' +
      jsonEscape(envOr("COMPUTERNAME", "")) +
      '"},'
  );
  out.push('"findings":[');
  for (var f = 0; f < findings.length; f++) {
    var item = findings[f];
    out.push("{");
    out.push('"plugin":"' + jsonEscape(item.plugin) + '",');
    out.push('"kind":"' + jsonEscape(item.kind) + '",');
    out.push('"severity":"' + jsonEscape(item.severity) + '",');
    out.push('"title":"' + jsonEscape(item.title) + '",');
    out.push('"detail":"' + jsonEscape(item.detail) + '",');
    out.push('"recommendation":"' + jsonEscape(item.recommendation) + '",');
    out.push('"noisy":' + (item.noisy ? "true" : "false") + ",");
    out.push('"leaves_artifacts":' + (item.leaves_artifacts ? "true" : "false") + ",");
    out.push('"object":"' + jsonEscape(item.object) + '",');
    out.push('"condition":"' + jsonEscape(item.condition) + '"');
    out.push("}" + (f + 1 < findings.length ? "," : ""));
  }
  out.push("],");
  out.push('"assessments":[],');
  out.push('"attack_paths":[],');
  out.push('"triage_decisions":[],');
  out.push('"plugins_run":[');
  for (var p = 0; p < collected.length; p++) {
    out.push('"' + collected[p] + '"' + (p + 1 < collected.length ? "," : ""));
  }
  out.push("],");
  out.push('"coverage":[');
  for (var c = 0; c < collected.length; c++) {
    var findingCount = 0;
    var pluginErrors = coverageErrors[collected[c]] || [];
    for (var cf = 0; cf < findings.length; cf++) {
      if (findings[cf].plugin === collected[c]) {
        findingCount++;
      }
    }
    out.push(
      '{"id":"' +
        collected[c] +
        '","status":"' +
        (pluginErrors.length > 0 ? "partial" : "ok") +
        '","findings":' +
        findingCount +
        ',"error":' +
        (pluginErrors.length > 0
          ? '"' + jsonEscape(pluginErrors.join("; ")) + '"'
          : "null") +
        ',"duration_ms":0},'
    );
  }
  for (var s = 0; s < delta.length; s++) {
    out.push(
      '{"id":"' +
        delta[s] +
        '","status":"skipped","findings":0,"error":"not collected by JScript fallback","duration_ms":0}' +
        (s + 1 < delta.length ? "," : "")
    );
  }
  out.push("],");
  out.push(
    '"notes":["JScript reports only registry and file-presence data it directly collected.","Service/task/DLL ACLs and effective policy are unavailable; native equivalence is not claimed."]'
  );
  out.push("}");
  WScript.Echo(out.join(""));
}

var findings = collectFindings();
if (wantJson) {
  emitJson(findings);
  WScript.Quit(0);
}

WScript.Echo("=== StealthyPrivesc Windows JScript enum ===");
WScript.Echo("LEGAL: Authorized use only.");
WScript.Echo("");

WScript.Echo("[*] env identity");
WScript.Echo("USERDOMAIN=" + wsh.ExpandEnvironmentStrings("%USERDOMAIN%"));
WScript.Echo("USERNAME=" + wsh.ExpandEnvironmentStrings("%USERNAME%"));
WScript.Echo("COMPUTERNAME=" + wsh.ExpandEnvironmentStrings("%COMPUTERNAME%"));
WScript.Echo("");

WScript.Echo("[*] AlwaysInstallElevated (HKLM/HKCU)");
var hklm = readAie("HKLM");
var hkcu = readAie("HKCU");
WScript.Echo("HKLM=" + hklm + " HKCU=" + hkcu);
if (hklm === 1 && hkcu === 1) {
  WScript.Echo("FINDING: AlwaysInstallElevated fully enabled");
}
WScript.Echo("");

WScript.Echo("[*] credential file presence");
var paths = [
  "C:\\Windows\\Panther\\Unattend.xml",
  "C:\\Windows\\Panther\\unattend.xml",
  "C:\\Windows\\System32\\sysprep\\unattend.xml",
  "C:\\Windows\\System32\\config\\RegBack\\SAM"
];
for (var i = 0; i < paths.length; i++) {
  if (fso.FileExists(paths[i])) {
    WScript.Echo("FINDING: present " + paths[i]);
  }
}
WScript.Echo("");

WScript.Echo("[*] endpoint controls (AppLocker / WDAC / SmartScreen / AMSI)");
for (var fi = 0; fi < findings.length; fi++) {
  if (findings[fi].plugin === "windows.endpoint_controls") {
    WScript.Echo("FINDING: " + findings[fi].title + " — " + findings[fi].detail);
  }
}
try {
  var ss = wsh.RegRead(
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreenEnabled"
  );
  WScript.Echo("SmartScreenEnabled=" + ss);
} catch (e) {
  WScript.Echo("SmartScreenEnabled unreadable");
}
try {
  wsh.RegRead("HKLM\\SOFTWARE\\Microsoft\\AMSI\\FeatureBits");
  WScript.Echo("AMSI FeatureBits present");
} catch (e) {
  WScript.Echo("AMSI FeatureBits unreadable (providers may still be registered)");
}
WScript.Echo(
  "NOTE: if custom .exe is blocked, prefer enum.ps1 / enum.js / EnumTasks.csproj."
);
WScript.Echo(
  "NOTE: endpoint-bypass is alternate-path + validation; stronger AV interference is Planned separately."
);

WScript.Echo("");
WScript.Echo("Done. Enumeration only.");
