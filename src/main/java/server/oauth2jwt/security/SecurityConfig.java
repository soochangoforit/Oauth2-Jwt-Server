package server.oauth2jwt.security;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import server.oauth2jwt.filter.CustomAuthenticationFilter;
import server.oauth2jwt.filter.CustomAuthorizationFilter;
import server.oauth2jwt.manager.CustomAuthenticationManager;
import server.oauth2jwt.service.JwtService;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final CustomAuthenticationManager customAuthenticationManager;
    private final JwtService jwtService;

    private final OAuth2SuccessHandler successHandler; // OAuth2 로그인 성공후 처리하는 핸들러

    private final PrincipalOauth2UserService principalOauth2UserService; // oauth2

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(customAuthenticationManager,jwtService);
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                .authorizeRequests().antMatchers("/api/login","/signUp", "/api/token/refresh").permitAll()
                .antMatchers(GET, "/api/users/**").hasAnyAuthority("ROLE_USER")
                .antMatchers(POST, "/api/user/save/**", "/api/writeTest").hasAnyAuthority("ROLE_USER")
                .anyRequest().authenticated()


                // 추가 필요
                .and()
                .addFilter(customAuthenticationFilter) // 인증 filter
                .addFilter(new CustomAuthorizationFilter(customAuthenticationManager))   // 인가 filter

                .oauth2Login()
                .successHandler(successHandler)
                .userInfoEndpoint()
                .userService(principalOauth2UserService);




        return http.build();
    }


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/static/**");
    }

}
