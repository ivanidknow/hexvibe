// Vulnerable: VUL-CVE-2021-29527
#include <algorithm>
#include <vector>

#define EIGEN_USE_THREADS
...
    }

    CHECK_GT(output_width, 0);
    CHECK_GT(output_height, 0);
    int filter_left_offset;
    int filter_top_offset;
...
    const int filter_value_count = filter_width * filter_height * input_depth;
    const int64 patches_per_chunk =
        kMaxChunkSize / (filter_value_count * sizeof(T1));
