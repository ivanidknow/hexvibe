// Vulnerable: VUL-CVE-2012-1108
// Next the number of fields in the comment vector.

  int commentFields = data.mid(pos, 4).toUInt(false);
  pos += 4;

...
  pos += 4;

  for(int i = 0; i < commentFields; i++) {

    // Each comment field is in the format "KEY=value" in a UTF8 string and has
...
    int commentSeparatorPosition = comment.find("=");

    String key = comment.substr(0, commentSeparatorPosition);
