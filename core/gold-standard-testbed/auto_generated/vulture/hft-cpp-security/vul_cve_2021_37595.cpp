// Vulnerable: VUL-CVE-2021-37595
if (fileContentsRequest->dwFlags == FILECONTENTS_SIZE)
		{
			*((UINT32*)&pData[0]) =
			    clipboard->fileDescriptor[fileContentsRequest->listIndex]->nFileSizeLow;
...
		{
			BOOL bRet;
			bRet = wf_cliprdr_get_file_contents(
			    clipboard->file_names[fileContentsRequest->listIndex], pData,
