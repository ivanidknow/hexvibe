// Vulnerable: VUL-CVE-2021-29520
}

    ConvBackpropDimensions dims;
    OP_REQUIRES_OK(context, ConvBackpropComputeDimensions(
...
      input_shape = context->input(0).shape();
    }

    ConvBackpropDimensions dims;
...
    }
...
    }

    ConvBackpropDimensions dims;
