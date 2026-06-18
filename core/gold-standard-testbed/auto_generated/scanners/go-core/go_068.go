// Vulnerable: GO-068
session.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteNoneMode,
    }
    session.Save(r, w)
}
func setSessionWithSameSiteStrict(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")
