// Vulnerable: HFT-9182
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_52b_badSink(data);
