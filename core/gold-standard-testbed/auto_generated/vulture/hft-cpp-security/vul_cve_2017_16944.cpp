// Vulnerable: VUL-CVE-2017-16944
JH/34 Bug 2199: fix a use-after-free while reading smtp input for header lines.
      A crafted sequence of BDAT commands could result in in-use memory beeing
      freed.
// --- receive.c ---
  empty header, and set next = NULL to indicate no data line. */

  if (ptr == 0 && ch == '.' && (smtp_input || dot_ends))
    {
    ch = (receive_getc)(GETC_BUFFER_UNLIMITED);
// --- smtp_in.c ---
				    (int)chunking_state, chunking_data_left);
...
    HAD(SCH_DATA);

    DATA_BDAT:		/* Common code for DATA and BDAT */
