# Bootlin ARM cross-compiler (Windows MinGW)
$gccPath = "$PSScriptRoot\..\gcc_win\arm-gnu-toolchain-13.2.Rel1-mingw-w64-i686-arm-none-linux-gnueabihf\bin\arm-none-linux-gnueabihf-gcc.exe"

# Check if compiler exists
if (-not (Test-Path $gccPath)) {
    Write-Host "ERROR: ARM compiler not found at: $gccPath"
    Write-Host "Run the toolchain download from README.md"
    exit 1
}

# Compile statically
& $gccPath main.c -o orbic_app -static

if ($?) {
    Write-Host "Build Successful: orbic_app"
    Get-Item orbic_app | Select-Object Name, Length, LastWriteTime
}
else {
    Write-Host "Build Failed: orbic_app"
}

# Build the boot helper if source exists
if (Test-Path "dagshell_boot.c") {
    & $gccPath dagshell_boot.c -o dagshell_boot -static
    if ($?) {
        Write-Host "Build Successful: dagshell_boot"
        Get-Item dagshell_boot | Select-Object Name, Length, LastWriteTime
    }
    else {
        Write-Host "Build Failed: dagshell_boot"
    }
}
else {
    Write-Host "Build Failed"
}
