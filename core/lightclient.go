package core

import "math"

func getSubtreeIndex(index uint64) uint64 {
	return uint64(index % uint64(math.Pow(2., math.Log2(float64(index)))))
}
