# Vulnerable: FAS-065
os.system(cmd)
def safe_no_exec():
    response = client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "Hello"}])
