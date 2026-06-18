// Vulnerable: JAVA-127
await connection.raw('
  INSERT INTO  (id, character, cartoon, link)
  VALUES(
      '${event.id}',
      '${event.character}',
      '${event.cartoon}',
      '${event.link}'
  )
  ');
