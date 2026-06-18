// Vulnerable: GO-089
query := fmt.Sprintf("SELECT number, expireDate, cvv FROM creditcards WHERE customerId = %s", customerId)
    row, _ := postgresDb.QueryRow(ctx, query)
}
package main
import (
    "context"
    "database/sql"
    "fmt"
    "http"
    "github.com/jackc/pgx/v4"
...
// cf. https://github.com/returntocorp/semgrep-rules/issues/1249
func new() {
