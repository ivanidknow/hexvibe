# Vulnerable: VUL-CVE-2019-19648
*.trs
*.log
// --- BUILD.bazel ---
        "libyara/mem.c",
        "libyara/modules.c",
        #"libyara/modules/cuckoo.c",  # TODO(cblichmann): Add Jansson JSON depenency
        "libyara/modules/dex.c",
        #"libyara/modules/demo.c",    # Disabled
        "libyara/modules/dotnet.c",
        "libyara/modules/elf.c",
        "libyara/modules/hash.c",
...
if DEX_MODULE
MODULES += modules/dex.c
endif
