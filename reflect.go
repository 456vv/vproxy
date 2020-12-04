package vproxy
import (
    "reflect"
    "fmt"
)

func ForType(x interface{}, all bool) string {
    return forType(x, "", "", 0, all)
}
func forType(x interface{}, str string, flx string, floor int, all bool) string {
    var (
        v, z reflect.Value
        f reflect.StructField
        t reflect.Type
        k interface{}
        s string
    )
    v, ok := x.(reflect.Value)
    if !ok {
		v = reflect.ValueOf(x)
    }
    v = inDirect(v)
    if v.Kind() != reflect.Struct {
        s += fmt.Sprintf("无法解析(%s): %#v\r\n", v.Kind(), x)
        return s
    }
    t = v.Type()
    for i := 0; i < t.NumField(); i++ {
        f = t.Field(i)
        if f.Name != "" && !all && (f.Name[0]  < 65 || f.Name[0] > 90) {
        	continue
        }
        z = inDirect(v.Field(i))
        if z.IsValid(){
	        k = z
	        if z.CanInterface() {
	        	k = typeSelect(z)
	        }
        }
        s += fmt.Sprintf("%s %v %v %v\t%v `%v` = %v\r\n", flx+str, f.Index, f.PkgPath, f.Name, f.Type, f.Tag, k)
        if z.Kind() == reflect.Struct{
        	floor++
            s += forType(z, str, flx+"  ", floor, all)
        }
    }
    return s
}

func typeSelect(v reflect.Value) interface{} {
    switch v.Kind() {
    case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
        return v.Int()
    case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
        return v.Uint()
    case reflect.Float32, reflect.Float64:
        return v.Float()
    case reflect.Bool:
        return v.Bool()
    case reflect.Complex64, reflect.Complex128:
        return v.Complex()
    case reflect.Invalid:
        return nil
    case reflect.String:
        return v.String()
   	case reflect.UnsafePointer:
   		return v.Pointer()
    case reflect.Slice, reflect.Array:
        if v.CanInterface() {
            return v.Interface()
        }
        
        l := v.Len()
        c := v.Cap()
        vet := reflect.SliceOf(v.Elem().Type())
        cv := reflect.MakeSlice(vet, l, c)
        for i:=0; i<l; i++ {
        	cv = reflect.Append(cv, reflect.ValueOf(typeSelect(v.Index(i))))
        }
        return cv.Interface()
    default:
    	//Interface
    	//Map
    	//Struct
    	//Chan
    	//Func
    	//Ptr
        if v.CanInterface() {
            return v.Interface()
        }
    }
    
   panic(fmt.Errorf("该类型 %s，无法转换为 interface 类型", v.Kind()))
}

func inDirect(v reflect.Value) reflect.Value {
	for ; v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface; v = v.Elem() {}
    return v
}
