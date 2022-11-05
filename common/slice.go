package common

func Contains(items []string, s string) bool {
	for _, item := range items {
		if item == s {
			return true
		}
	}
	return false
}
