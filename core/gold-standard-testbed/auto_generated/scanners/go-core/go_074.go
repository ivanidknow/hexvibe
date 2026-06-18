// Vulnerable: GO-074
func HiddenGoroutine() {
    go func() {
        fmt.Println("hello world")
    }()
}
