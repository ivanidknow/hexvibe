// Vulnerable: VUL-CVE-2017-11328
if (array->items == NULL)
  {
    count = yr_max(64, (index + 1) * 2);

    array->items = (YR_ARRAY_ITEMS*) yr_malloc(
...
  {
    count = array->items->count * 2;
    array->items = (YR_ARRAY_ITEMS*) yr_realloc(
        array->items,
// --- test-rules.c ---
...
  set_integer(2, module_object, "integer_array[%i]", 2);

  set_string("foo", module_object, "string_array[%i]", 0);
