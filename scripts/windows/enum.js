// StealthyPrivesc JScript fallback (cscript) — authorized assessments only.
// Quiet-leaning WMI / WScript enumeration. No exploitation.

var wsh = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var authorized = false;
for (var a = 0; a < WScript.Arguments.Count; a++) {
  var arg = String(WScript.Arguments.Item(a)).toLowerCase();
  if (arg === "--authorized" || arg === "--i-understand-authorized-use-only") {
    authorized = true;
  }
}
if (wsh.ExpandEnvironmentStrings("%STEALTHY_AUTHORIZED%") === "1") {
  authorized = true;
}
if (!authorized) {
  WScript.Echo("Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1");
  WScript.Quit(2);
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
function readAie(root) {
  try {
    var key = root + "\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
    return wsh.RegRead(key + "\\AlwaysInstallElevated");
  } catch (e) {
    return null;
  }
}
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
  } catch (e) {}
}
if (applocker.length > 0) {
  WScript.Echo(
    "FINDING: AppLocker SrpV2 EnforcementMode readable for: " + applocker.join(",")
  );
} else {
  WScript.Echo(
    "AppLocker EnforcementMode values not readable (policy may still exist)"
  );
}
try {
  var vbs = wsh.RegRead(
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity"
  );
  WScript.Echo("DeviceGuard VBS=" + vbs);
  if (vbs === 1) {
    WScript.Echo("FINDING: VBS enabled (WDAC/CI stack may be active)");
  }
} catch (e) {
  WScript.Echo("DeviceGuard VBS unreadable");
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
  // Presence probe: reading the key default often fails; try a nested path pattern via Providers.
  wsh.RegRead("HKLM\\SOFTWARE\\Microsoft\\AMSI\\FeatureBits");
  WScript.Echo("AMSI FeatureBits present");
} catch (e) {
  WScript.Echo("AMSI FeatureBits unreadable (providers may still be registered)");
}
WScript.Echo(
  "NOTE: if custom .exe is blocked, prefer enum.ps1 / enum.js / EnumTasks.csproj."
);
WScript.Echo(
  "NOTE: this script does not disable AppLocker, WDAC, SmartScreen, AMSI, or AV/EDR."
);

WScript.Echo("");
WScript.Echo("Done. Enumeration only.");
