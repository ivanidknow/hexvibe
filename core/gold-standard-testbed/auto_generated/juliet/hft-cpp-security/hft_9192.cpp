// Vulnerable: HFT-9192
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_63b_badSink(&data);
