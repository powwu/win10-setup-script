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
         -FilePath 'powershell' `
         -ArgumentList (
             #flatten to single array
             '-File', $MyInvocation.MyCommand.Source, $args `
               | %{ $_ }
         ) `
           -Verb RunAs
       exit
   }

#example program, this will be ran as admin
$args
Pause

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
    $installationDir = "%appdata%\win10-setup-script"

    $username = Read-Host 'Enter your VM username: '
    $pass = Read-Host "Enter password for $username: "
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $registryPath 'AutoAdminLogon' -Value "1" -Type String
    Set-ItemProperty $registryPath 'DefaultUsername' -Value "$username" -type String
    Set-ItemProperty $registryPath 'DefaultPassword' -Value "$pass" -type String

    # Virtio driver installation
    Write-Host "\n\n### INSTALL WINFSP ###"
    $fileName = "winfsp.msi"
    $expectedHash = "6324dc81194a6a08f97b6aeca303cf5c2325c53ede153bae9fc4378f0838c101" # Replace with the known hash
    Invoke-WebRequest "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi" -Output "$installationDir\$fileName"
    Check-Hash $installationDir $fileName $expectedHash
    "$installationDir\$fileName"

    Write-Host "\n\n### INSTALL WINFSP ###"
    $fileName = "winfsp.msi"
    $expectedHash = "6324dc81194a6a08f97b6aeca303cf5c2325c53ede153bae9fc4378f0838c101"
    Invoke-WebRequest https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi -Output "$installationDir\$fileName"
    Check-Hash $installationDir $fileName $expectedHash
    Start-Process -FilePath "$installationDir\$fileName"


    Write-Host "\n\n### INSTALL VIRTIO-WIN-GT ###"
    $fileName = "virtio-win-gt.msi"
    $expectedHash = "20a15bc93da585f90b4ca3b315652a9478e4c4a76f444d379b357167d727fee4"
    Invoke-WebRequest "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-x64.msi" -Output "$installationDir\$fileName"
    Check-Hash $installationDir $fileName $expectedHash
    Start-Process -FilePath "$installationDir\$fileName"

    Write-Host "\n\n### SET UP VIRTIO-FS SERVICE ###"
    cmd sc.exe create VirtioFsSvc binpath="(your binary location)\virtiofs.exe" start=auto depend="WinFsp.Launcher/VirtioFsDrv" DisplayName="Virtio FS Service"


    # OpenGL setup
}

Main-Func
