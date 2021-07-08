package tools

import "github.com/ori-shem-tov/vrf-oracle/models"

// A VrfRequestsHeap is a min-heap of VrfRequests.
type VrfRequestsHeap []models.VrfRequest

func (h VrfRequestsHeap) Len() int           { return len(h) }
func (h VrfRequestsHeap) Less(i, j int) bool { return h[i].BlockNumber < h[j].BlockNumber }
func (h VrfRequestsHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *VrfRequestsHeap) Push(x interface{}) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(models.VrfRequest))
}

func (h *VrfRequestsHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}