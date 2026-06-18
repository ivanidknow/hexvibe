// Vulnerable: HFT-9195
int data;
void (*funcPtr) (int) = CWE126_Buffer_Overread__CWE129_rand_65b_badSink;
data = -1;
data = RAND32();
funcPtr(data);
