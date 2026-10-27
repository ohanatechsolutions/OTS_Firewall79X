#define AppVersion "0.1.0"
[Setup]
AppId={{36E7B1AA-C968-453E-BAFC-5528B5F269E6}
AppName=OTS Firewall79X
AppVersion={#AppVersion}
AppPublisher=Ohana Tech Solutions
DefaultDirName={autopf}\OTS Firewall79X
DefaultGroupName=OTS Firewall79X
UninstallDisplayIcon={app}\OTS Firewall79X.exe
OutputDir=..\artifacts\release
OutputBaseFilename=OTS-Firewall79X-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
PrivilegesRequired=admin
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
InfoBeforeFile=..\docs\INSTALLER_NOTICE.txt
[Files]
Source: "..\artifacts\publish\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\artifacts\publish\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\artifacts\publish\recovery\*"; DestDir: "{app}\recovery"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\docs\RECOVERY.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\KNOWN_LIMITATIONS.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\EXTERNAL_TOOLS.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\artifacts\SBOM.json"; DestDir: "{app}\service"; Flags: ignoreversion
[Icons]
Name: "{group}\OTS Firewall79X"; Filename: "{app}\OTS Firewall79X.exe"
Name: "{group}\OTS Firewall79X Recovery"; Filename: "{app}\recovery\OTS.Firewall79X.Recovery.exe"
Name: "{autodesktop}\OTS Firewall79X"; Filename: "{app}\OTS Firewall79X.exe"
[Code]
function RunChecked(FileName, Params: String): Boolean;
var ExitCode: Integer;
begin
  Result := Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ExitCode) and (ExitCode = 0);
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Helper: String;
begin
  Result := '';
  Helper := ExpandConstant('{app}\recovery\OTS.Firewall79X.Recovery.exe');
  if FileExists(Helper) then
    if not RunChecked(Helper, '--uninstall --quiet') then
      Result := 'Existing service could not be safely stopped and restored. Use OTS Recovery before upgrading.';
end;
procedure CurStepChanged(CurStep: TSetupStep);
var ExitCode: Integer; Sc, BinaryPath: String;
begin
  if CurStep = ssPostInstall then begin
    Sc := ExpandConstant('{sys}\sc.exe');
    BinaryPath := ExpandConstant('{app}\service\OTS.Firewall79X.Service.exe');
    Exec(Sc, 'delete OTSFirewall79X', '', SW_HIDE, ewWaitUntilTerminated, ExitCode);
    if not RunChecked(Sc, 'create OTSFirewall79X binPath= "\"' + BinaryPath + '\"" start= auto DisplayName= "OTS Firewall79X Security Service"') then
      RaiseException('Service registration failed. Installation cannot be considered successful.');
    if not RunChecked(Sc, 'failure OTSFirewall79X reset= 86400 actions= restart/5000/restart/15000/restart/60000') then
      RaiseException('Service recovery configuration failed.');
    if not RunChecked(Sc, 'start OTSFirewall79X') then
      RaiseException('Service could not start. Open the installer log and OTS Recovery.');
  end;
end;
function InitializeUninstall(): Boolean;
begin
  Result := RunChecked(ExpandConstant('{app}\recovery\OTS.Firewall79X.Recovery.exe'), '--uninstall --quiet');
  if not Result then MsgBox('Safe restoration failed. Uninstall has stopped so recovery files remain available.', mbError, MB_OK);
end;
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var ExitCode: Integer;
begin
  if CurUninstallStep = usUninstall then
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete OTSFirewall79X', '', SW_HIDE, ewWaitUntilTerminated, ExitCode);
end;
