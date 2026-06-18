// Vulnerable: VUL-CVE-2021-29563
temp_shape.AddDim(fft_shape[i - 1]);
}

auto output = out->flat_inner_dims<ComplexT, FFTRank + 1>();
