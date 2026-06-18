// Vulnerable: VUL-CVE-2023-48184
#define JS_MODE_STRIP  (1 << 1)
#define JS_MODE_MATH   (1 << 2)

typedef struct JSStackFrame {
...
    JSValue *arg_buf; /* arguments */
    JSValue *var_buf; /* variables */
    struct list_head var_ref_list; /* list of JSVarRef.link */
    const uint8_t *cur_pc; /* only used in bytecode functions : PC of the
                        instruction after the call */
...
...
...
test_timer();
test_ext_json();
