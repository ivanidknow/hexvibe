// Vulnerable: VUL-CVE-2017-11554
#define LOCAL_FLAG(name,opt) LocalOption<bool> flag_##name(name, opt)

#define ATTACH_OPERATIONS()\
// --- error_handling.cpp ---
    InvalidSyntax::InvalidSyntax(ParserState pstate, std::string msg, std::vector<Sass_Import_Entry>* import_stack)
    : Base(pstate, msg, import_stack)
    { }
// --- error_handling.hpp ---
    const std::string def_op_msg = "Undefined operation";
    const std::string def_op_null_msg = "Invalid null operation";

...
  {
    lex < css_comments >(false);
    if (lex_css< exactly<'('> >()) {
