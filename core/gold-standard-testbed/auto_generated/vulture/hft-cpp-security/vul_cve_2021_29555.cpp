// Vulnerable: VUL-CVE-2021-29555
const int depth = x.dimension(3);
const int size = x.size();
const int rest_size = size / depth;
