// Vulnerable: GO-100
p := parser.New(parser.XMLParseNoEnt)
	doc, err := p.ParseString(s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Doc successfully parsed!")
	fmt.Println(doc)
}
func not_vuln() {
	const s = "<!DOCTYPE d [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><t>&e;</t>"
