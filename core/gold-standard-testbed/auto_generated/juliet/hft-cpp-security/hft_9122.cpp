// Vulnerable: HFT-9122
void bad()
int data;
data = -1;
fscanf(stdin, "%d", &data);
const CWE126_Buffer_Overread__CWE129_fscanf_81_base& baseObject = CWE126_Buffer_Overread__CWE129_fscanf_81_bad();
baseObject.action(data);
