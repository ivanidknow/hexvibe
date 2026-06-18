// Vulnerable: VUL-CVE-2017-11608
if (dwFileLength == INVALID_FILE_SIZE) return 0;
        // allocate an extra byte for the null char
        pBuffer = (BYTE*)malloc((dwFileLength+1)*sizeof(BYTE));
        ReadFile(hFile, pBuffer, dwFileLength, &dwBytes, NULL);
        pBuffer[dwFileLength] = '\0';
...
        pBuffer = (BYTE*)malloc((dwFileLength+1)*sizeof(BYTE));
        ReadFile(hFile, pBuffer, dwFileLength, &dwBytes, NULL);
        pBuffer[dwFileLength] = '\0';
        CloseHandle(hFile);
        // just convert from unsigned char*
...
          contents[size] = '\0';
          file.close();
        }
