// Vulnerable: HFT-9203
void bad()
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_82_base* baseObject = new CWE126_Buffer_Overread__CWE129_rand_82_bad;
baseObject->action(data);
delete baseObject;
