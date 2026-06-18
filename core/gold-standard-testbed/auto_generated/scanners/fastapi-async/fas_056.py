# Vulnerable: FAS-056
model = genai.GenerativeModel(
    "gemini-pro",
    safety_settings=safety_config
)
