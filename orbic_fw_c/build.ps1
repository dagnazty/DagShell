$compilerPath = "C:\Program Files (x86)\Arm GNU Toolchain arm-none-linux-gnueabihf\14.3 rel1\bin"
$env:PATH = "$compilerPath;" + $env:PATH

# Compile statically to avoid libc dependencies on the target
arm-none-linux-gnueabihf-gcc main.c -o orbic_app -static

if ($?) {
    Write-Host "Build Successful: orbic_app"
    # Show file info
    ls orbic_app
} else {
    Write-Host "Build Failed"
}
