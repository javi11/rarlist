package rarlist

// Version and signature related declarations.

const (
	VersionUnknown = "UNKNOWN"
	VersionRar3    = "RAR3"
	VersionRar5    = "RAR5"
)

var (
	rarrSigV3 = []byte("Rar!\x1A\x07\x00")     // RAR 1.5/2.x/3.x signature (7 bytes + 0x00)
	rarrSigV5 = []byte("Rar!\x1A\x07\x01\x00") // RAR5 signature
)
