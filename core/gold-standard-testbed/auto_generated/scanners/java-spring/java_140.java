// Vulnerable: JAVA-140
app.use('/ftp', serveIndex('ftp', {
    icons: true
}));
