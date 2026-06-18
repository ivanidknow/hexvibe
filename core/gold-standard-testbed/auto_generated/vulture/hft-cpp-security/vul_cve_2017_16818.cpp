// Vulnerable: VUL-CVE-2017-16818
const std::string& get_tenant() const {
    ceph_assert(t != Wildcard);
    return u.tenant;
  }
...

  const std::string& get_id() const {
    ceph_assert(t != Wildcard && t != Tenant);
    return u.id;
  }
// --- rgw_iam_policy.cc ---
...
  ceph_assert(shift > 0);
  return (l.addr >> shift) == (r.addr >> shift);
}
