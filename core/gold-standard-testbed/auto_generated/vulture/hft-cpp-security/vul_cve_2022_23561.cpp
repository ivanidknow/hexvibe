// Vulnerable: VUL-CVE-2022-23561
}

template <KernelType kernel_type>
TfLiteStatus EvalFloat(TfLiteContext* context, TfLiteNode* node,
...
        return kTfLiteError;
      }

      if (sparsity.dim_metadata_size == kDimMetadataSizeRandomSparse) {
...
        // Random sparse.
...
            GetTensorData<float>(output),
            CpuBackendContext::GetFromContext(context));
      } else {
