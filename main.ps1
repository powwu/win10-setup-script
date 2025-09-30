# Run script as follows:
# iex (irm 'https://powwu.sh/win10-setup.ps1')

# Prompt for elevation (from https://serverfault.com/a/1058407; thank you!)
if (!
    #current role
    (New-Object Security.Principal.WindowsPrincipal(
         [Security.Principal.WindowsIdentity]::GetCurrent()
         #is admin?
     )).IsInRole(
         [Security.Principal.WindowsBuiltInRole]::Administrator
     )
   ) {
       #elevate script and exit current non-elevated runtime
       Start-Process `
         -FilePath (Join-Path $PSHOME 'powershell.exe') `
         -ArgumentList (
             #flatten to single array
             '-NoProfile','-ExecutionPolicy','Bypass',
             '-File', $MyInvocation.MyCommand.Source, $args `
               | %{ $_ }
         ) `
           -Verb RunAs
       exit
   }

#example program, this will be ran as admin
# $args
# Pause

function Check-Hash($installationDir, $fileName, $expectedHash) {
    $calculatedHash = Get-FileHash -Algorithm SHA256 -Path "$installationDir\$fileName" | Select-Object -ExpandProperty Hash

    if ($calculatedHash -ne $expectedHash) {
        throw "Error: Hash $calculatedHash does not match expected hash $expectedHash for file $fileName"
    }
}

function Main-Func() {
    # Configure automatic login
    Write-Host "### CONFIGURE AUTOMATIC LOGIN ###"
    $installationDir = "$env:APPDATA\win10-setup-script"
    if (-not (Test-Path $installationDir)) { New-Item -ItemType Directory -Path $installationDir -Force | Out-Null }

    $username = Read-Host 'Enter your VM username'
    $pass = Read-Host "Enter password for $username"
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $registryPath 'AutoAdminLogon' -Value "1"
    Set-ItemProperty $registryPath 'DefaultUsername' -Value "$username"
    Set-ItemProperty $registryPath 'DefaultPassword' -Value "$pass"

    # Virtio driver installation
    Write-Host "\n\n### INSTALL WINFSP ###"
    $fileName = "winfsp.msi"
    $expectedHash = "6324dc81194a6a08f97b6aeca303cf5c2325c53ede153bae9fc4378f0838c101"
    Invoke-WebRequest "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi" -OutFile "$installationDir\$fileName"
    Check-Hash $installationDir $fileName $expectedHash
    Start-Process -FilePath "$installationDir\$fileName" -Wait

    Write-Host "\n\n### INSTALL VIRTIO-WIN-GT ###"
    $fileName = "virtio-win-gt.msi"
    $expectedHash = "20a15bc93da585f90b4ca3b315652a9478e4c4a76f444d379b357167d727fee4"
    Invoke-WebRequest "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-x64.msi" -OutFile "$installationDir\$fileName"
    Check-Hash $installationDir $fileName $expectedHash
    Start-Process -FilePath "$installationDir\$fileName" -Wait

    Write-Host "\n\n### SET UP VIRTIO-FS SERVICE ###"
    sc.exe create VirtioFsSvc binPath= "\"C:\Program Files\Virtio-Win\VioFS\virtiofs.exe\"" start= auto depend= "WinFsp.Launcher/VirtioFsDrv" DisplayName= "Virtio FS Service

# 7z installation
Write-Host "`n`n### INSTALL 7-ZIP ###"
    $sevenZipMsi = "7zip-x64.msi"
    $sevenZipUrl = "https://sourceforge.net/projects/sevenzip/files/7-Zip/25.01/7z2501-x64.msi/download"
    Invoke-WebRequest $sevenZipUrl -OutFile "$installationDir\$sevenZipMsi"
    Start-Process msiexec.exe -ArgumentList "/i `"$installationDir\$sevenZipMsi`" /qn /norestart" -Wait
    $sevenZipExe = "$env:ProgramFiles\7-Zip\7z.exe"
    if (-not (Test-Path $sevenZipExe)) { $sevenZipExe = "${env:ProgramW6432}\7-Zip\7z.exe" }
    if (-not (Test-Path $sevenZipExe)) { $sevenZipExe = "${env:ProgramFiles(x86)}\7-Zip\7z.exe" }
    if (-not (Test-Path $sevenZipExe)) { throw "7-Zip CLI not found after install." }

    # OpenGL setup
    Write-Host "`n`n### INSTALL+SETUP OPENGL ###"
    $fileName = "mesa3d-25.2.1-release-msvc.7z"
    $expectedHash = "ba0fee635e66753a64bc6e96bd9f89031e014e7fd3e442308af5cfee3edb201f"
    Invoke-WebRequest "https://github.com/pal1000/mesa-dist-win/releases/download/25.2.1/$fileName" -OutFile "$installationDir\$fileName"
    Check-Hash $installationDir $fileName $expectedHash
    $mesaOutDir = "$installationDir\mesa3d"
    if (Test-Path $mesaOutDir) { Remove-Item -Recurse -Force $mesaOutDir }
    New-Item -ItemType Directory -Path $mesaOutDir | Out-Null
    Start-Process -FilePath $sevenZipExe -ArgumentList "x `"$installationDir\$fileName`" -y -o`"$mesaOutDir`"" -Wait
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c systemwidedeploy.cmd" -WorkingDirectory $mesaOutDir -Wait

    # Wormhole installation
    Write-Host "`n`n### INSTALL WORMH0LE.EXE (GLOBAL) ###"

    # source URL (single-file executable)
    $wormholeUrl = "https://powwu.sh/wormhole.exe"
    $exeName    = "wormhole.exe"

    $expectedHash = "3070dfb895630fc01b4deabeffc3574681bb63f1dbd82f959aa663a6e09891fe"

    # Use existing $installationDir if available; otherwise fall back to TEMP
    if (-not (Get-Variable -Name installationDir -Scope 1 -ErrorAction SilentlyContinue)) {
        $tmpInstallDir = Join-Path $env:TEMP 'win10-setup-script'
    } else {
        $tmpInstallDir = $installationDir
    }
    if (-not (Test-Path $tmpInstallDir)) { New-Item -ItemType Directory -Path $tmpInstallDir -Force | Out-Null }

    $downloadPath = Join-Path $tmpInstallDir $exeName

    Write-Host "Downloading wormhole -> $downloadPath"
    Invoke-WebRequest -Uri $wormholeUrl -OutFile $downloadPath -UseBasicParsing

    if ($expectedHash -and $expectedHash.Trim() -ne "") {
        if (Get-Command -Name Check-Hash -ErrorAction SilentlyContinue) {
            Check-Hash $tmpInstallDir $exeName $expectedHash
        } else {
            $calculated = (Get-FileHash -Algorithm SHA256 -Path $downloadPath).Hash
            if ($calculated.ToLower() -ne $expectedHash.ToLower()) {
                throw "Wormhole SHA256 mismatch: got $calculated expected $expectedHash"
            }
        }
    }

    # Target place for a system-wide install
    $targetDir  = Join-Path $env:ProgramFiles 'Wormhole'
    $targetPath = Join-Path $targetDir $exeName

    if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }

    # Move/copy the binary into Program Files (overwrite if present)
    Copy-Item -Path $downloadPath -Destination $targetPath -Force

    # Ensure executable bit is OK (normal for .exe). Optionally set ACLs (here we ensure Users can read/execute):
    try {
        icacls $targetPath /grant "Users:(RX)" /T | Out-Null
    } catch { Write-Host "Warning: failed to adjust ACLs: $_" }

    # Add folder to MACHINE PATH if not already present
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (-not ($machinePath -like "*$targetDir*")) {
        $newMachinePath = $machinePath.TrimEnd(';') + ';' + $targetDir
        [Environment]::SetEnvironmentVariable('Path', $newMachinePath, 'Machine')
        Write-Host "Added $targetDir to machine PATH."
        # Broadcast environment change so most new processes see it without logout/reboot
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class NativeMethods {
    [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, UInt32 Msg, UIntPtr wParam, string lParam, UInt32 fuFlags, UInt32 uTimeout, out UIntPtr lpdwResult);
}
"@
        $HWND_BROADCAST = [intptr]0xffff
        $WM_SETTINGCHANGE = 0x001A
        $null = [NativeMethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [uintptr]0, "Environment", 0, 1000, [ref]0)
    } else {
        Write-Host "$targetDir already in machine PATH."
    }

    # Update current session PATH so the installed binary is immediately usable in this script
    if (-not ($env:Path -like "*$targetDir*")) { $env:Path += ";$targetDir" }

    Write-Host "Wormhole installed to: $targetPath"
}

Main-Func
