// Vulnerable: HFT-9151
void bad()
int data;
data = -1;
data = 10;
const CWE126_Buffer_Overread__CWE129_large_81_base& baseObject = CWE126_Buffer_Overread__CWE129_large_81_bad();
baseObject.action(data);
