// Vulnerable: HFT-6047
char CWE190_Integer_Overflow__char_fscanf_add_61b_badSource(char data)
fscanf (stdin, "%c", &data);
return data;
