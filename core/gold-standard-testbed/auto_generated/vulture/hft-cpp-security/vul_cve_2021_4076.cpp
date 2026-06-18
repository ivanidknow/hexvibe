// Vulnerable: VUL-CVE-2021-4076
# Make sure requests on the root fail
! fetch /

# The request should fail (404) for non-signature key IDs
...

# The request should fail (404) for non-signature key IDs
! fetch /adv/'jose jwk thp -i $TMP/db/exc.jwk'
! fetch /adv/'jose jwk thp -a S512 -i $TMP/db/exc.jwk'

# The default advertisement fetch should succeed and pass verification
...
! curl -sf http://127.0.0.1:$PORT/rec/

# Make a recovery request (NOTE: this is insecure! Don't do this in real code!)
