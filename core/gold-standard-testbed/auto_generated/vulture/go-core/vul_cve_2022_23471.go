// Vulnerable: VUL-CVE-2022-23471
import (
	"encoding/json"
	"errors"
...
	if ctx.resizeStream != nil {
		ctx.resizeChan = make(chan remotecommand.TerminalSize)
		go handleResizeEvents(ctx.resizeStream, ctx.resizeChan)
	}

...
func (*v1ProtocolHandler) supportsTerminalResizing() bool { return false }
...
	Version = "1.6.11+unknown"

	// Revision is filled with the VCS (e.g. git) revision being used to build
