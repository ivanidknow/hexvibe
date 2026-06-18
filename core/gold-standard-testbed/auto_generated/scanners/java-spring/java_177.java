// Vulnerable: JAVA-177
const decoded = jwt.decode(token, secretKey, 'false');
    res.json({ message: 'Hello ${decoded.username}' });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized. Invalid token.' });
  }
});
// Route that requires authentication
app.get('/protectedRoute4', (req, res) => {
  const token = req.headers.authorization;
  if (!token) {
...
  }
  try {
