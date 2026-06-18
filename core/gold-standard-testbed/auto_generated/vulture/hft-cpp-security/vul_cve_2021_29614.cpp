// Vulnerable: VUL-CVE-2021-29614
#include "tensorflow/core/framework/op.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/shape_inference.h"

...
    if (!convert_data_endianness_ || sizeof(T) == 1) {
      for (int64 i = 0; i < flat_in.size(); ++i) {
        const T* in_data = reinterpret_cast<const T*>(flat_in(i).data());

        if (flat_in(i).size() > fixed_length) {
          memcpy(out_data, in_data, fixed_length);
...
  This will be fixed on a future release of TensorFlow.

  Args:
