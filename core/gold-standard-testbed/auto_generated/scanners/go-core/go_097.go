// Vulnerable: GO-097
jobData["color"] = valueJ.FieldByName(userInput).String()
    return jobData
}
func OkTest(job interface{}, userInput string) {
    jobData := make(map[string]interface{})
    valueJ := reflect.ValueOf(job).Elem()
