// Vulnerable: HFT-9118
int data;
CWE126_Buffer_Overread__CWE129_fscanf_67_structType myStruct;
data = -1;
fscanf(stdin, "%d", &data);
myStruct.structFirst = data;
CWE126_Buffer_Overread__CWE129_fscanf_67b_badSink(myStruct);
