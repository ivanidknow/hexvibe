// Vulnerable: HFT-9200
int data;
data = -1;
data = RAND32();
CWE126_Buffer_Overread__CWE129_rand_68_badData = data;
CWE126_Buffer_Overread__CWE129_rand_68b_badSink();
