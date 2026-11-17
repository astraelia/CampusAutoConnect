#ifndef AppVersion
  #error Pass the application version with /DAppVersion
#endif
#define ProjectURL "https://github.com/astraelia/CampusAutoConnect"

[Setup]
AppId={{6F55B87D-81B2-49C3-8A42-19041AEF0419}
AppName=校园网连接助手
AppVersion={#AppVersion}
AppPublisher=Campus AutoConnect
AppPublisherURL={#ProjectURL}
AppSupportURL={#ProjectURL}/issues
AppUpdatesURL={#ProjectURL}/releases/latest
DefaultDirName={localappdata}\Programs\CampusAutoConnect
DefaultGroupName=校园网连接助手
DisableDirPage=no
DisableProgramGroupPage=yes
AlwaysShowDirOnReadyPage=yes
PrivilegesRequired=lowest
MinVersion=10.0
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
UninstallDisplayIcon={app}\CampusAutoConnect.exe
CloseApplications=yes
RestartApplications=no
SetupIconFile=..\src\campus_autoconnect\assets\app.ico
VersionInfoVersion={#AppVersion}.0
VersionInfoProductName=Campus AutoConnect
VersionInfoProductVersion={#AppVersion}.0
OutputDir=..\dist
OutputBaseFilename=CampusAutoConnect-{#AppVersion}-setup-win-x64
WizardStyle=modern
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "..\dist\CampusAutoConnect-{#AppVersion}-win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\校园网连接助手"; Filename: "{app}\CampusAutoConnect.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\校园网连接助手"; Filename: "{app}\CampusAutoConnect.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\CampusAutoConnect.exe"; Description: "打开校园网连接助手"; WorkingDir: "{app}"; Flags: postinstall skipifsilent unchecked nowait
