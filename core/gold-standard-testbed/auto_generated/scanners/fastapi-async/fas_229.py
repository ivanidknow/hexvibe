# Vulnerable: FAS-229
from xml.etree import ElementTree
    tree = ElementTree.parse('country_data.xml')
    root = tree.getroot()
def ok():
