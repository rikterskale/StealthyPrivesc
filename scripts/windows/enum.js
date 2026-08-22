// StealthyPrivesc JScript fallback (cscript) — authorized assessments only.
// Quiet-leaning WMI / WScript enumeration. No exploitation.

var wsh = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");

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
WScript.Echo("Done. Enumeration only.");
