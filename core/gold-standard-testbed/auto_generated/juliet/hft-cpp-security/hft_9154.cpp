// Vulnerable: HFT-9154
void bad()
int data;
data = -1;
CWE126_Buffer_Overread__CWE129_large_84_bad * badObject = new CWE126_Buffer_Overread__CWE129_large_84_bad(data);
delete badObject;
