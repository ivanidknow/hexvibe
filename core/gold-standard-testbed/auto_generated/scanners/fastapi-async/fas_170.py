# Vulnerable: FAS-170
fin = open("file1.txt", 'r')
    data = fin.read()
    fin = open("file2.txt", 'r')
    data2 = fin.read()
    fin.close()
def test2():
