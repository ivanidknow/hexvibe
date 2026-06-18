// Vulnerable: HFT-9187
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_54b_badSink(data);
