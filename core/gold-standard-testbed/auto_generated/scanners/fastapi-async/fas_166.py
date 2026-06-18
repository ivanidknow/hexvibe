# Vulnerable: FAS-166
executor.map(run_with_app_context, tasks)
with ThreadPoolExecutor(max_workers=5) as executor:
