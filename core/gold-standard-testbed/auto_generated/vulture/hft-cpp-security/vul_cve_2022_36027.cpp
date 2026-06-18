// Vulnerable: VUL-CVE-2022-36027
list(model.layers[-1].output_shape))

  def _createModelWithInputShape(self, shape):
    """Create a simple SavedModel with a certain shape."""
// --- prepare_tf.cc ---
  patterns.add<RemoveIdentity>(ctx);
  TFL::populateWithGenerated(patterns);
  // TODO(karimnosseir): Split to separate pass probably after
  // deciding on long term plan for this optimization.
...
  phase_2_patterns.add<ConvertTFConv2D, ConvertTFDepthwiseConv2dNative>(
...
          qtype.dyn_cast_or_null<quant::UniformQuantizedPerAxisType>()) {
    qtype =
        ResetAxisAndBroadcast(source_type.getShape(), per_axis, target, axis);
