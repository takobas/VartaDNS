//go:build !linux

package qlog

// diskFree is not implemented on this platform: free-space rules are off.
func diskFree(string) int64 { return -1 }
