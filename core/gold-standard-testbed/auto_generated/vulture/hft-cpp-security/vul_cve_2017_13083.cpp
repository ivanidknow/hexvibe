// Vulnerable: VUL-CVE-2017-13083
DWORD error_code = GetLastError();

	if ((error_code >> 16) != 0x8009)
		return WindowsErrorString();

...
	case CRYPT_E_NO_TRUSTED_SIGNER:
		return "None of the signers of the cryptographic message or certificate trust list is trusted.";
	default:
		static_sprintf(error_string, "Unknown PKI error 0x%08lX", error_code);
...
...
					break;

				memset(&si, 0, sizeof(si));
