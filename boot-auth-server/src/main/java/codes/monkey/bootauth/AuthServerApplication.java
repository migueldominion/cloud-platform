package codes.monkey.bootauth;

import java.util.Locale;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import codes.monkey.bootauth.security.google2fa.CustomAuthenticationProvider;
import codes.monkey.bootauth.security.google2fa.CustomWebAuthenticationDetailsSource;

@SpringBootApplication
//@EnableResourceServer
class AuthServerApplication extends WebMvcConfigurerAdapter{

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("login");
        registry.addViewController("/admin.html");
        registry.addViewController("/badUser.html");
        registry.addViewController("/changePassword.html");
        registry.addViewController("/console.html");
        registry.addViewController("/emailError.html");
        registry.addViewController("/forgetPassword.html");
        registry.addViewController("/home.html");
        registry.addViewController("/homePage.html");
        registry.addViewController("/logout.html");
        registry.addViewController("/qrcode.html");
        registry.addViewController("/registration.html");
        registry.addViewController("/registrationCaptcha.html");
        registry.addViewController("/registrationConfirm.html");
        registry.addViewController("/successRegister.html");
        registry.addViewController("/updatePassword.html");
    }

    @Configuration
    @Order(-20)
    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        private UserDetailsService userDetailsService;

        @Autowired
        private CustomWebAuthenticationDetailsSource authenticationDetailsSource;

        @Autowired
        private LogoutSuccessHandler myLogoutSuccessHandler;

        @Override
        @Bean
		public AuthenticationManager authenticationManagerBean() throws Exception {
          return super.authenticationManagerBean();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http
                .formLogin().loginPage("/login").authenticationDetailsSource(authenticationDetailsSource).permitAll()
                    .and().httpBasic().and()
                    .requestMatchers()
                    //specify urls handled
                    .antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
                    .antMatchers("/fonts/**", "/js/**", "/css/**", "/sbadmin2/**")
                    // add templates only here if need to be protected by login page
                    .antMatchers("/admin.html","/console.html","/changePassword.html","/home.html","/homePage.html","/logout.html")
                    .antMatchers("/login*","/login*", "/logout*", "/signin/**", "/signup/**", "/customLogin",
	                        "/user/registration*", "/registrationConfirm*", "/expiredAccount*", "/registration*",
	                        "/badUser*", "/user/resendRegistrationToken*" ,"/forgetPassword*", "/user/resetPassword*",
	                        "/user/changePassword*", "/emailError*", "/resources/**","/old/user/registration*","/successRegister*","/qrcode*")
                    .antMatchers("/user/updatePassword*","/user/savePassword*","/updatePassword*")
                    .and()
                    .authorizeRequests()
                    .antMatchers("/fonts/**", "/js/**", "/css/**", "/sbadmin2/**").permitAll()
                    //.antMatchers("/registration.html").permitAll
	                .antMatchers("/login*","/login*", "/logout*", "/signin/**", "/signup/**", "/customLogin",
	                        "/user/registration*", "/registrationConfirm*", "/expiredAccount*", "/registration*",
	                        "/badUser*", "/user/resendRegistrationToken*" ,"/forgetPassword*", "/user/resetPassword*",
	                        "/user/changePassword*", "/emailError*", "/resources/**","/old/user/registration*","/successRegister*","/qrcode*").permitAll()
	                //.antMatchers("/user/updatePassword*","/user/savePassword*","/updatePassword*").hasAuthority("CHANGE_PASSWORD_PRIVILEGE")
	                .antMatchers("/admin*").hasAuthority("WRITE_PRIVILEGE")
                    .anyRequest().authenticated()
                    .and()
                    .logout()
						.logoutSuccessHandler(myLogoutSuccessHandler)
						.invalidateHttpSession(false)
						.logoutSuccessUrl("/auth/logout.html?logSucc=true")
						.deleteCookies("JSESSIONID")
						.permitAll();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(authProvider());
            /*auth.inMemoryAuthentication()
                    .withUser("reader")
                    .password("reader")
                    .authorities("ROLE_READER")
                    .and()
                    .withUser("writer")
                    .password("writer")
                    .authorities("ROLE_READER", "ROLE_WRITER")
                    .and()
                    .withUser("guest")
                    .password("guest")
                    .authorities("ROLE_GUEST");*/
        }

        // beans

		@Bean
		public DaoAuthenticationProvider authProvider() {
			final CustomAuthenticationProvider authProvider = new CustomAuthenticationProvider();
			authProvider.setUserDetailsService(userDetailsService);
			authProvider.setPasswordEncoder(encoder());
			return authProvider;
		}

		@Bean
		public PasswordEncoder encoder() {
			return new BCryptPasswordEncoder(11);
		}

	    @Bean
	    public SessionRegistry sessionRegistry() {
	        return new SessionRegistryImpl();
	    }
    }

    @Configuration
    @EnableAuthorizationServer
	@PropertySource({ "classpath:persistence.properties" })
    static class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        @Qualifier("authenticationManagerBean")
        AuthenticationManager authenticationManager;

		@Autowired
		private Environment env;
		
		@Value("classpath:schema.sql")
		private Resource schemaScript;
		
		@Value("classpath:data.sql")
		private Resource dataScript;
		
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.jdbc(dataSource());
            /*clients.inMemory()
                    .withClient("web-app")
                    .scopes("read")
                    .autoApprove(true)
                    .accessTokenValiditySeconds(600)
                    .refreshTokenValiditySeconds(600)
                    .authorizedGrantTypes("implicit", "refresh_token", "password", "authorization_code");*/
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer()).authenticationManager(authenticationManager);
        }


        @Bean
        TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource());
        }

        @Bean
        protected JwtAccessTokenConverter jwtTokenEnhancer() {
            KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                    new ClassPathResource("jwt.jks"), "mySecretKey".toCharArray());
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            converter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));
            return converter;
        }
		
		 // JDBC token store configuration

		@Bean
		public DataSourceInitializer dataSourceInitializer(final DataSource dataSource) {
			final DataSourceInitializer initializer = new DataSourceInitializer();
			initializer.setDataSource(dataSource);
			initializer.setDatabasePopulator(databasePopulator());
			return initializer;
		}

		private DatabasePopulator databasePopulator() {
			final ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
			populator.addScript(schemaScript);
			populator.addScript(dataScript);
			return populator;
		}

		@Bean
		public DataSource dataSource() {
			final DriverManagerDataSource dataSource = new DriverManagerDataSource();
			dataSource.setDriverClassName(env.getProperty("jdbc.driverClassName"));
			dataSource.setUrl(env.getProperty("jdbc.url"));
			
			dataSource.setUsername(env.getProperty("jdbc.user"));
			dataSource.setPassword(env.getProperty("jdbc.pass"));
			return dataSource;
		}

    }

    @Bean
    public LocaleResolver localeResolver() {
        SessionLocaleResolver slr = new SessionLocaleResolver();
        slr.setDefaultLocale(Locale.ENGLISH);
        return slr;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
        lci.setParamName("lang");
        return lci;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }

    public static void main(String[] args) {
    	SpringApplication.run(AuthServerApplication.class, args);
    }
}
