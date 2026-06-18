// Vulnerable: GO-106
Director: func(req *http.Request) {
		modifyRequest(req)
	},
}
_ = rp
f := Fake{
