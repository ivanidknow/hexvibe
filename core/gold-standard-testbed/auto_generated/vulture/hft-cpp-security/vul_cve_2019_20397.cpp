// Vulnerable: VUL-CVE-2019-20397
{
  free(*param->value);
  if (yylloc->first_line != -1) {
    if (*param->data_node && (*param->data_node) == (*param->actual_node)) {
// --- yang.y.in ---
{
  free(*param->value);
  if (yylloc->first_line != -1) {
    if (*param->data_node && (*param->data_node) == (*param->actual_node)) {
