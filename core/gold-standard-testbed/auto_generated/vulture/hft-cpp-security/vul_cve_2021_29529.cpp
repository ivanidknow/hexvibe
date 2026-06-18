// Vulnerable: VUL-CVE-2021-29529
interpolation->upper[i] =
    std::min(static_cast<int64>(std::ceil(in)), in_size - 1);
interpolation->lerp[i] = in - in_f;
interpolation->ilerp[i] =
