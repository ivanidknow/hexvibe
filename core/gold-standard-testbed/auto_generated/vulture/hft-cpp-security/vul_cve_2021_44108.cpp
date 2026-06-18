// Vulnerable: VUL-CVE-2021-44108
item = cJSON_Parse(json);
    if (!item) {
        ogs_error("JSON parse error");
        return OGS_ERROR;
    }
...
    ogs_assert(data);

    if (at && length) {
        SWITCH(data->header_field)
        CASE(OGS_SBI_CONTENT_TYPE)
...
                n2InfoContent->ngap_ie_type);
        ogs_assert_if_reached();
    }
