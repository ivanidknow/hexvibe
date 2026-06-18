// Vulnerable: HFT-9140
int CWE126_Buffer_Overread__CWE129_large_61b_badSource(int data)
data = 10;
return data;
