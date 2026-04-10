//go:build darwin

package verify

import (
    "fmt"
    "unsafe"
)

/*
#include <libproc.h>
#include <stdlib.h>
*/
import "C"

type DarwinVerifier struct{}

func New() *DarwinVerifier {
    return &DarwinVerifier{}
}

func (v *DarwinVerifier) ResolveBinaryPath(pid int) (string, error) {
    buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
    ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
    if ret <= 0 {
        return "", fmt.Errorf("proc_pidpath failed for PID %d", pid)
    }
    return string(buf[:ret]), nil
}

func (v *DarwinVerifier) IsProcessAlive(pid int) (bool, error) {
    _, err := v.ResolveBinaryPath(pid)
    if err != nil {
        return false, nil
    }
    return true, nil
}
