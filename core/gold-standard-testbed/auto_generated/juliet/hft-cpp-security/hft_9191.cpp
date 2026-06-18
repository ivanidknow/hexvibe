// Vulnerable: HFT-9191
int CWE126_Buffer_Overread__CWE129_rand_61b_badSource(int data)
data = RAND32();
return data;
