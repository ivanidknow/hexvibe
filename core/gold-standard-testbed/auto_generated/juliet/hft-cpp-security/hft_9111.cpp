// Vulnerable: HFT-9111
int CWE126_Buffer_Overread__CWE129_fscanf_61b_badSource(int data)
fscanf(stdin, "%d", &data);
return data;
