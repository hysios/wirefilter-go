package wirefilter

// #cgo LDFLAGS: -L./lib -lwirefilter_ffi -Wl,-rpath=./lib
// #cgo CFLAGS: -I./include
// #cgo amd64 386 CFLAGS: -DX86=1
// #include <stdbool.h>
// #include "wirefilter.h"
// typedef struct {
//    uint8_t _res2;
//    wirefilter_filter_ast_t *ast;
// } wire_ast;
// typedef struct {
// 	uint8_t _res1;
// 	wirefilter_rust_allocated_str_t msg;
// } wire_err;
// typedef struct {
//     const char *data;
//     size_t length;
// } rust_allocated_str;
import "C"

import (
	"errors"
	"unsafe"
)

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

type ParseFilter struct {
	ptr unsafe.Pointer

	Ast *Ast
}

type Ast struct {
	ptr *C.wirefilter_filter_ast_t
}

func (scheme *WirefilterScheme) ParerFilter(exp string) (*ParseFilter, error) {
	var result = &ParseFilter{}
	r := C.wirefilter_parse_filter(scheme.ptr, C.wirefilter_externally_allocated_str_t(RString(exp)))
	result.ptr = unsafe.Pointer(&r)

	u := result.ptr
	success := (*(*C.uint8_t)(u))
	if success > 0 {
		ast := (*C.wire_ast)(u)
		result.Ast = &Ast{ptr: ast.ast}
	} else {
		_err := (*C.wire_err)(u)
		return nil, errors.New(GString(C.rust_allocated_str(_err.msg)))
	}

	return result, nil
}

func (parse *ParseFilter) Close() error {
	r := (*C.wirefilter_parsing_result_t)(parse.ptr)
	C.wirefilter_free_parsing_result(*r)
	return nil
}

func RString(s string) C.rust_allocated_str {
	return C.rust_allocated_str{
		length: C.size_t(len(s)),
		data:   C.CString(s),
	}
}

func GString(s C.rust_allocated_str) string {
	return string(C.GoBytes(unsafe.Pointer(s.data), C.int(s.length)))
}
