// Vulnerable: GO-067
user_id = r.query.params.user_id
    user_obj := RetrieveUser(user_id)
    user_obj.account_id = r.query.params.account_id
    user_obj.save()
}
func augment(user_id int, augment_string string) int {
    return user_id
}
func MyHandlerOK(w http.ResponseWriter, r *http.Request) {
