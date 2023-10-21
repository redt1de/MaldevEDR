package util

import "fmt"

func FileSize(size int) string {
	const (
		B  = 1
		KB = 1024 * B
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
		PB = 1024 * TB
	)
	switch {
	case size < KB:
		return fmt.Sprintf("%dB", size)
	case size < MB:
		return fmt.Sprintf("%.2fKB", float64(size)/float64(KB))
	case size < GB:
		return fmt.Sprintf("%.2fMB", float64(size)/float64(MB))
	case size < TB:
		return fmt.Sprintf("%.2fGB", float64(size)/float64(GB))
	case size < PB:
		return fmt.Sprintf("%.2fTB", float64(size)/float64(TB))
	default:
		return fmt.Sprintf("%.2fPB", float64(size)/float64(PB))
	}
}
