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
    Set-ExecutionPolicy RemoteSigned -Force
    $installationDir = "$env:APPDATA\win10-setup-script"
    if (-not (Test-Path $installationDir)) { New-Item -ItemType Directory -Path $installationDir -Force | Out-Null }

    $username = Read-Host 'Enter your VM username: '
    $pass = Read-Host "Enter password for $username: "
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
    Start-Process -FilePath "$installationDir\$fileName"

    Write-Host "\n\n### INSTALL VIRTIO-WIN-GT ###"
    $fileName = "virtio-win-gt.msi"
    $expectedHash = "20a15bc93da585f90b4ca3b315652a9478e4c4a76f444d379b357167d727fee4"
    Invoke-WebRequest "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-x64.msi" -OutFile "$installationDir\$fileName"
    Check-Hash $installationDir $fileName $expectedHash
    Start-Process -FilePath "$installationDir\$fileName"

    Write-Host "\n\n### SET UP VIRTIO-FS SERVICE ###"
    sc.exe create VirtioFsSvc binPath= "\"(your binary location)\virtiofs.exe\"" start= auto depend= "WinFsp.Launcher/VirtioFsDrv" DisplayName= "Virtio FS Service"

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
}

Main-Func
