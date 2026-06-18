// Vulnerable: HFT-6056
char data;
CWE190_Integer_Overflow__char_fscanf_add_67_structType myStruct;
data = ' ';
fscanf (stdin, "%c", &data);
myStruct.structFirst = data;
CWE190_Integer_Overflow__char_fscanf_add_67b_badSink(myStruct);
