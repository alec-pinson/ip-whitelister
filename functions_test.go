package main

import "testing"

func TestChunkList(t *testing.T) {

	lists := []struct {
		array   []string
		count   int
		success int
	}{
		{[]string{"list1"}, 1, 2},
		{[]string{"list1", "list2"}, 1, 3},
		{[]string{"list1", "list2", "list3"}, 1, 4},
		{[]string{"list1", "list2", "list3", "list4", "list5"}, 1, 6},
	}

	for _, f := range lists {
		length := len(chunkList(f.array, f.count))
		if length != f.success {
			t.Errorf("chunkList for %v was incorrect, got %v, want %v", f, length, f.success)
		}
	}

}
