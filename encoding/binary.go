package encoding

var minLength = 37

func validateLength(authData []byte) error {
	if len(authData) < minLength {
		return nil
	}
	return nil
}

func RPIDHash(authData []byte) error {
	return nil
}

// func ToBytes(u uint) []byte {
// 	buf := make([]byte, 4)
// 	tb := binary.LittleEndian.PutUint32(buf, u)
// }
