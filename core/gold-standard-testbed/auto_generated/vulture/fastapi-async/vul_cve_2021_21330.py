# Vulnerable: VUL-CVE-2021-21330
web.normalize_path_middleware(append_slash=True, remove_slash=True)


async def test_bug_3669(aiohttp_client: Any):
// --- web_middlewares.py ---
            for path in paths_to_check:
                resolves, request = await _check_request_resolves(request, path)
                if resolves:
