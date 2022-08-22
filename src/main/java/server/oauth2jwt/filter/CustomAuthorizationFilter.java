package server.oauth2jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                                                throws IOException, ServletException {

        // refresh 요청 및 일반 권한이 필요없는 요청은 해당 필터를 거치지 않는다.
        // 대신 config에 해당 url에 대해서는 반드시 permitAll()이 이루어져야 한다.
        if(request.getServletPath().equals("/signUp") || request.getServletPath().equals("/api/login")|| request.getServletPath().equals("/api/token/refresh")) {
            log.info("request Servlet path : {}", request.getServletPath());
            filterChain.doFilter(request, response);
        }else{
            String authorizationHeader = request.getHeader(AUTHORIZATION);


            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
                try{
                    verifyTokenAndSetSecuritySession(authorizationHeader);

                    filterChain.doFilter(request, response);
                }catch(Exception exception){
                    // access token verify 실패시 에러 응답 , 해킹 당한 access token이거나, access token의 유효기간이 지난 경우
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());

                    Map<String , String> error = new HashMap<>();
                    error.put("error_message" , exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            }
        }


    }

    private void verifyTokenAndSetSecuritySession(String authorizationHeader) {
        String token = authorizationHeader.substring("Bearer ".length()); // access token
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

        JWTVerifier verifier = JWT.require(algorithm).build();

        // todo : accesstoken의 유효기간이 지난 경우, error를 내뱉어주고 있다.
        DecodedJWT decodedJWT = verifier.verify(token);

        Long id = Long.valueOf(decodedJWT.getSubject());
        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(id, null, authorities);

        // todo : 아직까지 이러한 과정으로 토큰을 뜯어서 보아도, 사용자가 어떤 권한을 가지는지만 알지
        //  해당 사용자가 자신 권한에게 맞는 url을 요청했는지 확인하지는 못한다. 권한에 맞는 url를 요청했는지 판단은 config에서 판단한다.

        // need to set this user the security context holder
        // hey, security !! this is the user here's , their username , roles , there what that can do in the application
        // so Spring is going to look at the user , look at their role , and determine what resources they can access
        // and what they can access, depending on the roles.
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }


}
