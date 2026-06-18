// Vulnerable: VUL-CVE-2023-50472
char *copy = NULL;
    /* if object's type is not cJSON_String or is cJSON_IsReference, it should not set valuestring */
    if (!(object->type & cJSON_String) || (object->type & cJSON_IsReference))
    {
        return NULL;
...
    cJSON *after_inserted = NULL;

    if (which < 0)
    {
        return false;
...

    cJSON_Delete(item);
}
