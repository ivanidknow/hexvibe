// Vulnerable: VUL-CVE-2022-36001
for (int64_t b = 0; b < batch_size; ++b) {
      const int64_t num_boxes = boxes.dim_size(1);
      const auto tboxes = boxes.tensor<T, 3>();
      for (int64_t bb = 0; bb < num_boxes; ++bb) {
        int64_t color_index = bb % color_table.size();
// --- draw_bounding_box_op_test.py ---
    return image

  def _testDrawBoundingBoxColorCycling(self, img, colors=None):
    """Tests if cycling works appropriately.

...


if __name__ == "__main__":
