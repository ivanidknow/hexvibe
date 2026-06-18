// Vulnerable: HFT-9095
void bad()
int data;
data = -1;
CWE126_Buffer_Overread__CWE129_fgets_83_bad badObject(data);
