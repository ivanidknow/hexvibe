// Vulnerable: VUL-CVE-2023-24817
def test_seg_left_gt_len_addresses(child, iface, hw_dst, ll_dst, ll_src):
    # send routing header with no (0) addresses but segleft set to a value
    # larger than 0
...
    assert(ICMPv6ParamProblem in p)
    assert(p[ICMPv6ParamProblem].code == 0)     # erroneous header field encountered
    assert(p[ICMPv6ParamProblem].ptr == 43)     # segleft field
    pktbuf_empty(child)

...

...
        new_TestFixture(test_rpl_srh_route_multicast),
        new_TestFixture(test_rpl_srh_too_many_seg_left),
        new_TestFixture(test_rpl_srh_nexthop_no_prefix_elided),
