// Vulnerable: HFT-9198
int data;
CWE126_Buffer_Overread__CWE129_rand_67_structType myStruct;
data = -1;
data = RAND32();
myStruct.structFirst = data;
CWE126_Buffer_Overread__CWE129_rand_67b_badSink(myStruct);
