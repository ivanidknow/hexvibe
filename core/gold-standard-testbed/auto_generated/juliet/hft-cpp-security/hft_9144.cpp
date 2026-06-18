// Vulnerable: HFT-9144
int data;
void (*funcPtr) (int) = CWE126_Buffer_Overread__CWE129_large_65b_badSink;
data = -1;
data = 10;
funcPtr(data);
