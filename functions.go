package main

// function to split an array of strings
func chunkList(array []string, count int) [][]string {
	lena := len(array)
	lenb := lena/count + 1
	b := make([][]string, lenb)

	for i, _ := range b {
		start := i * count
		end := start + count
		if end > lena {
			end = lena
		}
		b[i] = array[start:end]
	}

	return b
}
