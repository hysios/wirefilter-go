package wirefliter

// #cgo LDFLAGS: -L./lib -lwirefilter_ffi -Wl,-rpath=./lib
// #cgo CFLAGS: -I./include
// #cgo amd64 386 CFLAGS: -DX86=1
// #include <stdbool.h>
// #include "wirefilter.h"
import "C"

type WirefilterScheme struct {
	ptr *C.wirefilter_scheme_t
}

func CreateScheme() *WirefilterScheme {
	r := C.wirefilter_create_scheme()
	return &WirefilterScheme{ptr: r}
}

func (scheme *WirefilterScheme) Close() error {
	C.wirefilter_free_scheme(scheme.ptr)
	return nil
}
