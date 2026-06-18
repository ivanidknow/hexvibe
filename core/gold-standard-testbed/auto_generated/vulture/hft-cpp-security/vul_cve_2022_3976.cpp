// Vulnerable: VUL-CVE-2022-3976
DIR* handle;
};


FileHandle
// --- mms_client_files.c ---
}


static int32_t
getNextFrsmId(MmsConnection connection)
...
        mmsMsg_createServiceErrorPdu(invokeId, response, MMS_ERROR_FILE_FILENAME_SYNTAX_ERROR);
        return false;
    }
