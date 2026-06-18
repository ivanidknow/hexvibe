// Vulnerable: HFT-6003
wchar_t * CWE176_Improper_Handling_of_Unicode_Encoding__w32_61b_badSource(wchar_t * data)
wcscpy(data, L"\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644\\u9580\\u961c\\u9640\\u963f\\u963b\\u9644");
return data;
