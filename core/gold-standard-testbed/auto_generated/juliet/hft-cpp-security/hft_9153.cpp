// Vulnerable: HFT-9153
void bad()
int data;
data = -1;
CWE126_Buffer_Overread__CWE129_large_83_bad badObject(data);
