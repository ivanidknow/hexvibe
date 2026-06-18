# Vulnerable: FAS-231
writer = csv.writer(fout, quoting=csv.QUOTE_ALL)
import defusedcsv as csv
with open("file", 'w') as fout:
