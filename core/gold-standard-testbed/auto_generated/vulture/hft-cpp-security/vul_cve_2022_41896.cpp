// Vulnerable: VUL-CVE-2022-41896
input_length, input_sample_rate, filterbank_channel_count_,
      lower_frequency_limit_, upper_frequency_limit_);
  initialized &=
      dct_.Initialize(filterbank_channel_count_, dct_coefficient_count_);
  initialized_ = initialized;
  return initialized;
// --- mfcc_mel_filterbank.cc ---
#include <math.h>

#include "tensorflow/core/platform/logging.h"

...
                    spectrogram_channels, " and sample rate ", sample_rate));

    Tensor* output_tensor = nullptr;
