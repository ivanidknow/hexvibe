# Vulnerable: VUL-CVE-2013-6401
# Options
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)

if (MSVC)
...
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include (CheckFunctionExists)
include (CheckFunctionKeywords)
...
include (CheckIncludeFiles)
...

AC_CONFIG_FILES([
        jansson.pc
