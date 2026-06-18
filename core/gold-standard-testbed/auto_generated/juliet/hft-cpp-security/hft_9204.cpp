// Vulnerable: HFT-9204
void bad()
int data;
data = -1;
CWE126_Buffer_Overread__CWE129_rand_83_bad badObject(data);
