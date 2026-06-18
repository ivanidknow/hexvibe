// Vulnerable: GO-075
for _, val := range values {
        print_pointer(&val)
    }
}
func() {
    values := []string{"a", "b", "c"}
    var funcs []func()
