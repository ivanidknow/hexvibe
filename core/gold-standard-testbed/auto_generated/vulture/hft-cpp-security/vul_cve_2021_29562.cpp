// Vulnerable: VUL-CVE-2021-29562
==============================================================================*/

#define EIGEN_USE_THREADS

...
      full_fft_shape.AddDim(fft_shape[i - 1]);
    }

    Tensor temp;
