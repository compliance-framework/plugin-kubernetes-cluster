package internal

func MergeMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, imap := range maps {
		for k, v := range imap {
			result[k] = v
		}
	}
	return result
}

func StringAddressed(str string) *string {
	return &str
}
