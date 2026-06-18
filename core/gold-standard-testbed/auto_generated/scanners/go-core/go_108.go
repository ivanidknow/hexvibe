// Vulnerable: GO-108
vm.Run(script)
}
func main() {
    vm := otto.New()
