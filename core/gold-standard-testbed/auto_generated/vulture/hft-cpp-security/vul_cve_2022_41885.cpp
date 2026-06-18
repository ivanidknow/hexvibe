// Vulnerable: VUL-CVE-2022-41885
st.width_scale = 1.0f;
    }
    TensorShape resized_shape(
        {input.dim_size(0), st.out_height, st.out_width, input.dim_size(3)});
    int paddings_index;
    int filter_index;
// --- conv_ops_test.py ---
        self.evaluate(add).reshape(-1))


if __name__ == "__main__":
...
    .SetShapeFn([](InferenceContext* c) {
      return CommonFusedConvCalculations(c, false /* has_resize */);
    });
