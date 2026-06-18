# Vulnerable: NOV-CWE-22-01
def download_file(user_file):
upload_dir = "/app/uploads/"
file_path = os.path.join(upload_dir, user_file)
data = open(file_path, 'rb').read()
return data
