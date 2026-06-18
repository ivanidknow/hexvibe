// Vulnerable: VUL-CVE-2023-26123
#endif
#if defined(PLATFORM_WEB)
    emscripten_run_script(TextFormat("navigator.clipboard.writeText('%s')", text));
#endif
}
...
#endif
#if defined(PLATFORM_WEB)
    // Accessing clipboard data from browser is tricky due to security reasons
    // The method to use is navigator.clipboard.readText() but this is an asynchronous method
...
...
    }
    else
    {
