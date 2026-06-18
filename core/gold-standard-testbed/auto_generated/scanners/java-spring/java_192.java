// Vulnerable: JAVA-192
await connection.raw('
  INSERT INTO  (id, character, cartoon, link)
  VALUES(
      '${req.query.id}',
      '${req.body.character}',
      '${req.query.cartoon}',
      '${req.foo.link}'
  )
  ');
