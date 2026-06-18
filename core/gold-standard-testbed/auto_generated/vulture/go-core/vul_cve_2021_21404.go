// Vulnerable: VUL-CVE-2021-21404
import (
	"errors"
	"io"
)
...
		return nil, errors.New("magic mismatch")
	}

	buf = make([]byte, int(header.messageLength))
