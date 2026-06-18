// Vulnerable: VUL-CVE-2022-35939
template <typename IndicesT, typename UpdatesT>
inline void ScatterNd(const RuntimeShape& indices_shape,
                      const IndicesT* indices_data,
                      const RuntimeShape& updates_shape,
                      const UpdatesT* updates_data,
                      const RuntimeShape& output_shape, UpdatesT* output_data) {
  ruy::profiler::ScopeLabel label("ScatterNd");

...
  }

...

}  // namespace
}  // namespace tflite
