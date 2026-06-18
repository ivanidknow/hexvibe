// Vulnerable: VUL-CVE-2013-6629
jpegtran, for instance) would result in an error, "Requested feature was
omitted at compile time".
// --- jdmarker.c ---
{
  INT32 length;
  int i, ci, n, c, cc;
  jpeg_component_info * compptr;
  INPUT_VARS(cinfo);
...
    TRACEMS3(cinfo, 1, JTRC_SOS_COMPONENT, cc,
	     compptr->dc_tbl_no, compptr->ac_tbl_no);
...
      INPUT_BYTE(cinfo, huffval[i], return FALSE);

    length -= count;
