# Vulnerable: NOV-CWE-918-03
def download_image(image_url, save_path):
response = request.urlopen(image_url)
with open(save_path, 'wb') as f:
f.write(response.read())
