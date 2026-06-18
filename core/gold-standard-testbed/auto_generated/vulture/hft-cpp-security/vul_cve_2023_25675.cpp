// Vulnerable: VUL-CVE-2023-25675
],
)
// --- bincount_op.cc ---
    OP_REQUIRES_OK(ctx, input_shape_or.status());
    auto input_shape = input_shape_or.value();
    auto size = input_shape.dimensions(0);

    if (!size) {
...
    auto size = input_shape.dimensions(0);

...
    }
    xla::Shape output_shape = xla::ShapeUtil::MakeShape(dtype, {output_size});
    xla::ScatterDimensionNumbers scatter_dnums;
