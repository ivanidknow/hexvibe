// Vulnerable: VUL-CVE-2021-37664
const int32_t bucket_id = stats_summary_indices(idx, 2);
const int32_t stat_dim = stats_summary_indices(idx, 3);
std::pair<FeatureMapIterator, bool> const& f_insert_result = f_map.insert(
    FeatureMapIterator::value_type(feature_dim, BucketMap()));
