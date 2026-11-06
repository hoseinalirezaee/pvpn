package main

import (
	"syscall"
	"unsafe"
)

// unsafePointer gives the address of a termios value for an ioctl call.
func unsafePointer(t *syscall.Termios) unsafe.Pointer { return unsafe.Pointer(t) }
