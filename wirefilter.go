package wirefilter

//#cgo LDFLAGS: -L${SRCDIR}/lib -Wl,-rpath,${SRCDIR}/lib -lwirefilter_ffi
//#cgo CFLAGS: -I./include
//#include <stdbool.h>
//#include "wirefilter.h"
//typedef struct {
//	uint8_t _res2;
//	wirefilter_filter_ast_t *ast;
//} wirefilter_parsing_result_ok;
//typedef struct {
//	uint8_t _res1;
// 	wirefilter_rust_allocated_str_t msg;
//} wirefilter_parsing_result_err;
import "C"

import (
	"errors"
	"log"
	"net"
	"reflect"
	"unsafe"
)

type Type int

const (
	TYPE_IP    Type = C.WIREFILTER_TYPE_IP
	TYPE_BYTES Type = C.WIREFILTER_TYPE_BYTES
	TYPE_INT   Type = C.WIREFILTER_TYPE_INT
	TYPE_BOOL  Type = C.WIREFILTER_TYPE_BOOL
)

type Schema struct {
	ptr *C.wirefilter_scheme_t
	types map[string]Type
}

func NewSchema() *Schema {
	r := C.wirefilter_create_scheme()
	//fmt.Printf("%T:%v\n", r, unsafe.Pointer(r))
	return &Schema{ptr: r,
		types: make(map[string]Type)}
}

func (s *Schema) AddField(name string, type_ Type) {
	cName := C.CString(name)
	cNameSizeT := C.size_t(len(name))
	defer C.free(unsafe.Pointer(cName))

	C.wirefilter_add_type_field_to_scheme(s.ptr,
		C.wirefilter_externally_allocated_str_t{
			data: cName,
			length: cNameSizeT,
		}, C.wirefilter_type_t(type_)) // TODO: is this really safe?
	s.types[name] = type_
}

func (s *Schema) AddFields(fields map[string]Type) {
	for field, type_ := range fields {
		s.AddField(field, type_)
	}
}

func (s Schema) Parse(input string) (*AST, error) {
	cInput := C.CString(input)
	cInputSizeT := C.size_t(len(input))
	defer C.free(unsafe.Pointer(cInput))

	parsingResult := C.wirefilter_parse_filter(s.ptr,
		C.wirefilter_externally_allocated_str_t{
			data: cInput,
			length: cInputSizeT,
		})

	parsingResultPtr := unsafe.Pointer(&parsingResult)

	success := (*(*C.uint8_t)(parsingResultPtr))
	if success > 0 {
		_ok := (*C.wirefilter_parsing_result_ok)(parsingResultPtr)
		return &AST{ptr: _ok.ast}, nil
	} else {
		_err := (*C.wirefilter_parsing_result_err)(parsingResultPtr)
		s := C.wirefilter_rust_allocated_str_t(_err.msg)
		return nil, errors.New(string(C.GoBytes(unsafe.Pointer(s.data), C.int(s.length))))
	}
}

// TODO: wirefilter_free_parsing_result

func (s *Schema) Close() {
	C.wirefilter_free_scheme(s.ptr)
}

type AST struct {
	ptr *C.wirefilter_filter_ast_t
}

func (ast *AST) Compile() *Filter {
	compileResult := C.wirefilter_compile_filter(ast.ptr)
	return &Filter{
		ptr: compileResult,
	}
}

type Filter struct {
	ptr *C.wirefilter_filter_t
}

func (f *Filter) Execute(ctx *ExecutionContext) bool {
	r := C.wirefilter_match(f.ptr, ctx.ptr)
	return bool(r)
}

type ExecutionContext struct {
	ptr *C.wirefilter_execution_context_t
	schema *Schema
}

func NewExecutionContext(schema *Schema) *ExecutionContext {
	ctx := C.wirefilter_create_execution_context(schema.ptr)
	return &ExecutionContext{
		ptr: ctx,
		schema: schema,
	}
}

func (ctx *ExecutionContext) SetFieldValue(name string, value interface{}) {
	_, ok := ctx.schema.types[name]

	if !ok {
		return
	}

	cName := C.CString(name)
	cNameSizeT := C.size_t(len(name))
	defer C.free(unsafe.Pointer(cName))

	strTName := C.wirefilter_externally_allocated_str_t{
		data: cName,
		length: cNameSizeT,
	}

	switch value.(type) {
	case int:
		C.wirefilter_add_int_value_to_execution_context(
			ctx.ptr, strTName, C.int(value.(int)))
	case net.IP:
		ip := value.(net.IP)
		log.Print(ip)
		/*
		if value.(net.IP).To4() != nil {
			var ipv4 [4]C.uint8_t
			v := unsafe.Pointer(&ipv4)

			sh := (*reflect.SliceHeader)(v)
			sh.Data = uintptr(unsafe.Pointer(&ip[0]))
			sh.Len  = len(ip)

			C.wirefilter_add_ipv4_value_to_execution_context(
				ctx.ptr, strTName, &ipv4)
		} else {
			var ipv6 [16]C.uint8_t

			v := unsafe.Pointer(&ipv6)

			sh := (*reflect.SliceHeader)(v)
			sh.Data = uintptr(unsafe.Pointer(&ip[0]))
			sh.Len  = len(ip)

			C.wirefilter_add_ipv4_value_to_execution_context(
				ctx.ptr, strTName, &ipv6)
		}*/
	case []byte:
		buf := value.([]byte)
		C.wirefilter_add_bytes_value_to_execution_context(
			ctx.ptr, strTName, C.wirefilter_externally_allocated_byte_arr_t{
				data: (*C.uchar)(unsafe.Pointer(&buf[0])), // TODO: free here needed?
				length: C.size_t(len(buf)),
			})
	case string:
		buf := []byte(value.(string))
		ctx.SetFieldValue(name, buf)
	case bool:
		C.wirefilter_add_bool_value_to_execution_context(
			ctx.ptr, strTName, C._Bool(value.(bool)))
		break
	}
}

func (ctx *ExecutionContext) Close() {
	C.wirefilter_free_execution_context(ctx.ptr)
}

func Version() string {
	versionResult := C.wirefilter_get_version()
	return string(C.GoBytes(unsafe.Pointer(versionResult.data), C.int(versionResult.length)))
}

func IP2IP(ip net.IP) (ipv4 [4]C.uint8_t) {
	v := unsafe.Pointer(&ipv4)
	sh := (*reflect.SliceHeader)(v)
	sh.Data = uintptr(unsafe.Pointer(&ip[0]))
	sh.Len = len(ip)
	return
}
