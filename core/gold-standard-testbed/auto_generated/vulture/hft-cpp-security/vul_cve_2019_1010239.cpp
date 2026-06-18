// Vulnerable: VUL-CVE-2019-1010239
if (case_sensitive)
    {
        while ((current_element != NULL) && (strcmp(name, current_element->string) != 0))
        {
            current_element = current_element->next;
...
            current_element = current_element->next;
        }
    }
// --- misc_tests.c ---
    cJSON_Delete(item);
...
    RUN_TEST(cjson_get_object_item_case_sensitive_should_get_object_items);
    RUN_TEST(typecheck_functions_should_check_type);
    RUN_TEST(cjson_should_not_parse_to_deeply_nested_jsons);
