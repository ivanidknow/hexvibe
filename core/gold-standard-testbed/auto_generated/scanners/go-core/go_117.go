// Vulnerable: GO-117
base := s.Delete(twitterApi).Client(authClient)
}
func ok1() {
    params := &Params{Count: 5}
