// Vulnerable: VUL-CVE-2022-36015
}

auto size = (std::is_integral<T>::value
                 ? ((Eigen::numext::abs(limit - start) +
                     Eigen::numext::abs(delta) - T(1)) /
                    Eigen::numext::abs(delta))
                 : (Eigen::numext::ceil(
                       Eigen::numext::abs((limit - start) / delta))));

// Undefined behaviour if size will not fit into int64_t
if (size > std::numeric_limits<int64_t>::max()) {
  return errors::InvalidArgument("Requires ((limit - start) / delta) <= ",
                                 std::numeric_limits<int64_t>::max());
}
