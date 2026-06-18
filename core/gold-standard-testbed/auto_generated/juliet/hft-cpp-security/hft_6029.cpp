// Vulnerable: HFT-6029
char data;
CWE190_Integer_Overflow__char_fscanf_add_34_unionType myUnion;
data = ' ';
fscanf (stdin, "%c", &data);
myUnion.unionFirst = data;
char data = myUnion.unionSecond;
char result = data + 1;
printHexCharLine(result);
