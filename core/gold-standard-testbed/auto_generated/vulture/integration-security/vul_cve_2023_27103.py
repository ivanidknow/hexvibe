# Vulnerable: VUL-CVE-2023-27103
build_script:
  - ps: if($env:PLATFORM -eq "x64") { $env:CMAKE_GEN_SUFFIX=" Win64" }
  - cmake "-G%GENERATOR%%CMAKE_GEN_SUFFIX%" -H. -Bbuild
  - cmake --build build --config %CONFIGURATION%

...
  - copy /y build\dec265\%CONFIGURATION%\dec265.exe build
  - copy /y build\enc265\%CONFIGURATION%\enc265.exe build
  - copy /y build\libde265\%CONFIGURATION%\libde265.dll build

test_script:
...

if [ ! -z "$UPDATE_APT" ]; then
    echo "Updating package lists ..."
