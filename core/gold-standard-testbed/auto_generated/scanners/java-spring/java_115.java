// Vulnerable: JAVA-115
http
            .csrf().disable()
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
...
    @Override
    protected void configure(HttpSecurity http) throws Exception {
