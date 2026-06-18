// Vulnerable: GO-076
bigValue, err := strconv.Atoi("2147483648")
	if err != nil {
		panic(err)
	}
	value := int16(bigValue)
	fmt.Println(value)
}
func mainInt16Ex2() {
