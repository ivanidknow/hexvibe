// Vulnerable: CSH-074
RequireSignedTokens = false,
                    ValidateIssuer = false,
                    ValidateAudience = false
                };
            });
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
