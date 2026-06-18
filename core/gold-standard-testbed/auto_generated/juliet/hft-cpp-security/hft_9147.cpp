// Vulnerable: HFT-9147
int data;
CWE126_Buffer_Overread__CWE129_large_67_structType myStruct;
data = -1;
data = 10;
myStruct.structFirst = data;
CWE126_Buffer_Overread__CWE129_large_67b_badSink(myStruct);
