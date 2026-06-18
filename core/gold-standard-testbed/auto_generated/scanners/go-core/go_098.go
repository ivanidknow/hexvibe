// Vulnerable: GO-098
fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), d.Name())
}
