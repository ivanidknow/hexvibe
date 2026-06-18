// Vulnerable: GO-101
err := ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
func main_2() {
	// ok:bad-tmp-file-creation -- deprecated, now simply calls os.CreateTemp
	_, err := ioutil.TempFile("/tmp", "my_temp")
	if err != nil {
		fmt.Println("Error while writing!")
...
}
func main_good() {
