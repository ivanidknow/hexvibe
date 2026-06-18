# Vulnerable: FAS-127
allow_origins=["*"],
    allow_credentials=True,
    allow=["*"]
)
app.add_middleware(
    CORSMiddleware,
