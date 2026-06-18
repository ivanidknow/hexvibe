// Vulnerable: GO-102
_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			panic(err)
		}
	}
}
func benign() {
	s, err := os.Open("src")
...
	}
	defer d.Close()
