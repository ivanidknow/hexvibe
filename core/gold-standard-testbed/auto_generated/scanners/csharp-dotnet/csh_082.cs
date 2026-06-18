// Vulnerable: CSH-082
command.CommandText = String.Format("SELECT c.name AS column_name,t.name AS type_name,c.max_length,c.precision,c.scale,             CAST(CASE WHEN EXISTS(SELECT * FROM sys.index_columns AS i WHERE i.object_id=c.object_id AND i.column_id=c.column_id) THEN 1 ELSE 0 END AS BIT) AS column_indexed             FROM sys.columns AS c              JOIN sys.types AS t ON c.user_type_id=t.user_type_id              WHERE c.object_id = OBJECT_ID('{0}')              ORDER BY c.column_id;", sqli);
command.CommandTimeout = 15;
command.CommandType = CommandType.Text;
await using var connection = new SqlConnection(configuration.GetVaultConnectionString(sqli, "B", true));
await using var command = connection.CreateCommand();
