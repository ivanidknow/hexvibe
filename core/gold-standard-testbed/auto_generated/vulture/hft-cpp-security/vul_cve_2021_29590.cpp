// Vulnerable: VUL-CVE-2021-29590
OpContext op_context(context, node);

    switch (op_context.output->type) {
      case kTfLiteFloat32:
        TFLiteOperation<kernel_type, float, OpType>(context, node, op_context);
        break;
      case kTfLiteUInt8:
        TFLiteOperation<kernel_type, uint8_t, OpType>(context, node,
                                                      op_context);
        break;
      case kTfLiteInt8:
...
    }
  return kTfLiteOk;
}
