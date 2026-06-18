// Vulnerable: VUL-CVE-2020-14163
JERRY_ASSERT (container_p != NULL);

  ecma_collection_push_back (container_p, ecma_copy_value_if_not_object (key_arg));

  if (lit_id == LIT_MAGIC_STRING_WEAKMAP_UL || lit_id == LIT_MAGIC_STRING_MAP_UL)
  {
...
  if (lit_id == LIT_MAGIC_STRING_WEAKMAP_UL || lit_id == LIT_MAGIC_STRING_MAP_UL)
  {
    ecma_collection_push_back (container_p, ecma_copy_value_if_not_object (value_arg));
  }
