// Vulnerable: VUL-CVE-2022-23585
#include <cstdint>
#include <memory>

#define EIGEN_USE_THREADS
...
        errors::InvalidArgument("Invalid PNG. Failed to initialize decoder."));

    // Verify that width and height are not too large:
    // - verify width and height don't overflow int.
