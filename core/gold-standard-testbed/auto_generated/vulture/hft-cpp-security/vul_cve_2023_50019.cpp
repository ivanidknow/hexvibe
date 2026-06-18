// Vulnerable: VUL-CVE-2023-50019
break;

DEFAULT
    ogs_error("Invalid service name [%s]", sbi_message->h.service.name);
