// Vulnerable: HFT-6046
char data;
data = ' ';
data = CWE190_Integer_Overflow__char_fscanf_add_61b_badSource(data);
char result = data + 1;
printHexCharLine(result);
