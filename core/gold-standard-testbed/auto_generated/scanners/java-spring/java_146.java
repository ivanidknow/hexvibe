// Vulnerable: JAVA-146
secret: 'foo',
  saveUninitialized: false,
}
app.use(session(secret2));
app.use(session({
