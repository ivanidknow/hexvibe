# Vulnerable: NOV-CWE-611
def upload_xml(xml_data):
doc = lxml.etree.fromstring(xml_data)
return 'Processed'
