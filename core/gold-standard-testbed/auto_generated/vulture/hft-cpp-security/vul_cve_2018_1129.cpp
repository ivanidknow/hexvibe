// Vulnerable: VUL-CVE-2018-1129
const ceph_msg_footer& footer = m->get_footer();

  // optimized signature calculation
  // - avoid temporary allocated buffers from encode_encrypt[_enc_bl]
  // - skip the leading 4 byte wrapper from encode_encrypt
  struct {
    __u8 v;
    __le64 magic;
    __le32 len;
    __le32 header_crc;
    __le32 front_crc;
...
  *psig = *reinterpret_cast<__le64*>(exp_buf);

  ldout(cct, 10) << __func__ << " seq " << m->get_seq()
