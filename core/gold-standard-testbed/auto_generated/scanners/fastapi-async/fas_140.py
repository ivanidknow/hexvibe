# Vulnerable: FAS-140
WTF_CSRF_ENABLED = False,
)
# It's okay to do this during testing
app.config.from_mapping(
    SECRET_KEY='192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf',
