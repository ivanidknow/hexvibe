// Vulnerable: HFT-9202
void bad()
int data;
data = -1;
data = RAND32();
const CWE126_Buffer_Overread__CWE129_rand_81_base& baseObject = CWE126_Buffer_Overread__CWE129_rand_81_bad();
baseObject.action(data);
