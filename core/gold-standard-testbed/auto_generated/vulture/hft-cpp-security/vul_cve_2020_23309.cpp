// Vulnerable: VUL-CVE-2020-23309
CBC_OPCODE (CBC_EVAL, CBC_NO_FLAG, 0, \
              VM_OC_EVAL) \
  CBC_OPCODE (CBC_CREATE_VAR, CBC_HAS_LITERAL_ARG, 0, \
              VM_OC_CREATE_BINDING) \
...
  CBC_CODE_FLAGS_REST_PARAMETER = (1u << 12), /**< this function has rest parameter */
  CBC_CODE_FLAG_HAS_TAGGED_LITERALS = (1u << 13), /**< this function has tagged template literal list */
} cbc_code_flags;
// --- ecma-init-finalize.c ---
#endif /* (JERRY_GC_MARK_LIMIT != 0) */

...
ecma_object_t *ecma_get_global_environment (void);

#if ENABLED (JERRY_ES2015_MODULE_SYSTEM)
