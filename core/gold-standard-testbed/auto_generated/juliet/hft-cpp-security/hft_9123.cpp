// Vulnerable: HFT-9123
void bad()
int data;
data = -1;
fscanf(stdin, "%d", &data);
CWE126_Buffer_Overread__CWE129_fscanf_82_base* baseObject = new CWE126_Buffer_Overread__CWE129_fscanf_82_bad;
baseObject->action(data);
delete baseObject;
