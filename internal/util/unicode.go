package util

// DecodeRar3Unicode is exported inside internal tree for parser reuse.
// Simplified reconstruction of RAR3 Unicode names based on ASCII + encoded form.
func DecodeRar3Unicode(asciiPart, unicodeData []byte) string {
	if len(unicodeData) == 0 {
		return string(asciiPart)
	}
	result := make([]rune, 0, len(asciiPart))
	asciiPos := 0
	dataPos := 0
	var highByte byte
	for dataPos < len(unicodeData) {
		flags := unicodeData[dataPos]
		dataPos++
		var flagBits uint
		var flagCount int
		if flags&0x80 != 0 { // extended flag
			flagBits = uint(flags)
			bitCount := 1
			for (flagBits&(0x80>>bitCount) != 0) && dataPos < len(unicodeData) {
				flagBits = ((flagBits & ((0x80 >> bitCount) - 1)) << 8) | uint(unicodeData[dataPos])
				dataPos++
				bitCount++
			}
			flagCount = bitCount * 4
		} else {
			flagBits = uint(flags)
			flagCount = 4
		}
		for i := 0; i < flagCount; i++ {
			if asciiPos >= len(asciiPart) && dataPos >= len(unicodeData) {
				break
			}
			flagValue := (flagBits >> (i * 2)) & 0x03
			switch flagValue {
			case 0:
				if asciiPos < len(asciiPart) {
					result = append(result, rune(asciiPart[asciiPos]))
					asciiPos++
				}
			case 1:
				if dataPos < len(unicodeData) {
					result = append(result, rune(unicodeData[dataPos]))
					dataPos++
				}
			case 2:
				if dataPos < len(unicodeData) {
					low := unicodeData[dataPos]
					dataPos++
					result = append(result, rune(uint16(low)|uint16(highByte)<<8))
				}
			case 3:
				if dataPos < len(unicodeData) {
					highByte = unicodeData[dataPos]
					dataPos++
				}
			}
		}
	}
	for asciiPos < len(asciiPart) { // remaining ASCII
		result = append(result, rune(asciiPart[asciiPos]))
		asciiPos++
	}
	return string(result)
}
