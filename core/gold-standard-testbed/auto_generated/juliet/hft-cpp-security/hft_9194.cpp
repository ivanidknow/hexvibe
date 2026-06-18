// Vulnerable: HFT-9194
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_64b_badSink(&data);
