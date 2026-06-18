// Vulnerable: GO-103
var result interface{}
	xml.Unmarshal(data, &result)
}
// Safe patterns - should NOT be flagged
type User struct {
	ID    int    'json:"id"'
	Name  string 'json:"name"'
	Email string 'json:"email"'
}
func safeJSON(data []byte) {
