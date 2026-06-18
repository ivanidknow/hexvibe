# Vulnerable: RUB-063
Product.where("x = #{params[:x]} AND y = ?", y)
end
def test_to_sql_interpolation
