// Vulnerable: GO-091
l, err := net.Listen("tcp", ":2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
func main() {
