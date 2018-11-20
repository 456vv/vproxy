package vproxy
import (
    "reflect"
    "fmt"
)



//ForMethod 遍历方法
//  参：
//      x interface{}     类型
//  返：
//      string            字符串
//func ForMethod(x interface{}) string {
//    var t = reflect.TypeOf(x)
//    var s string
//    for i:=0; i<t.NumMethod(); i++ {
//        tm := t.Method(i)
//        s += fmt.Sprintf("%d %s %s\t\t= %v \n", tm.Index, tm.PkgPath, tm.Name, tm.Type)
//   }
//   return s
//}

//ForType 遍历字段
//  参：
//      x interface{}     类型
//  返：
//      string            字符串
//func ForType(x interface{}) string {
//    return forType(x, "")
//}
func forType(x interface{}, str string) string {
    var (
        v, z reflect.Value
        f reflect.StructField
        t reflect.Type
        k interface{}
        s string
    )

    v = reflect.ValueOf(x)
    v = inDirect(v)
    if v.Kind() == reflect.Invalid || v.Kind() != reflect.Struct {
        s += fmt.Sprintf("无法解析(%s): %#v\r\n", v.Kind(), x)
        return s
    }
    t = v.Type()
    for i := 0; i < t.NumField(); i++ {
        f = t.Field(i)
        z = inDirect(v.Field(i))
        k = typeSelect(z)
        s += fmt.Sprintf("%s %v %v %v\t%v `%v` = %v\r\n", str, f.Index, f.PkgPath, f.Name, f.Type, f.Tag, k)
        if z.Kind() == reflect.Struct && z.CanInterface() {
            s += forType(z.Interface(), "    "+str)
        }
    }
    return s
}



//TypeSelect 类型选择
//    参：
//      v reflect.Value        映射一种未知类型的变量
//    返：
//      interface{}            读出v的值
//func TypeSelect(v reflect.Value) interface{} {
//    return typeSelect(v)
//}
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
        case reflect.Slice, reflect.Array:
            if v.CanInterface() {
                return v.Interface()
            }
            var t []interface{}
            for i:=0; i<v.Len(); i++ {
                t = append(t, typeSelect(v.Index(i)))
            }
            return t
        default:
            if v.CanInterface() {
                return v.Interface()
            }
            return v.String()
    }
}

//InDirect 指针到内存
//    参：
//      v reflect.Value        映射引用为真实内存地址
//    返：
//      reflect.Value          真实内存地址
//func InDirect(v reflect.Value) reflect.Value {
//    return inDirect(v)
//}
func inDirect(v reflect.Value) reflect.Value {
	for ; v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface; v = v.Elem() {
    }
    return v
}

