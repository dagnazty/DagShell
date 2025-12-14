$compilerPath = "d:\Scripts\orbic\gcc\arm-gnu-toolchain-13.3.rel1-mingw-w64-i686-arm-none-linux-gnueabihf\bin"
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
