// Vulnerable: HFT-9152
void bad()
int data;
data = -1;
data = 10;
CWE126_Buffer_Overread__CWE129_large_82_base* baseObject = new CWE126_Buffer_Overread__CWE129_large_82_bad;
baseObject->action(data);
delete baseObject;
