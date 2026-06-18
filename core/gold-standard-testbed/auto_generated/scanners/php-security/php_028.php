// Vulnerable: PHP-028
DB::raw("SELECT * FROM users WHERE name = $name AND someproperty = foo"));
});
Route::get('safe-from-sql-injection', function($name) {
return DB::select(
