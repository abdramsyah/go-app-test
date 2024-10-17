package util

func FindFromSlice(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func PrependArray(x []interface{}, y interface{}) []interface{} {
	x = append(x, "")
	copy(x[1:], x)
	x[0] = y
	return x
}
