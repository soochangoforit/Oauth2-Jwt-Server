package server.oauth2jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import server.oauth2jwt.dto.request.LoginDto;
import server.oauth2jwt.manager.CustomAuthenticationManager;
import server.oauth2jwt.service.JwtService;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final CustomAuthenticationManager customAuthenticationManager;
    private final JwtService jwtService;

    // /login post 요청이 올때 해당 메소드를 우선적으로 거친다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 아이디 : username
        // 비밀번호 : password

        // 사용자가 입력했던 로그인 아이디, 비밀번호를 JSON형태로 받아서 갖는다.
        ObjectMapper objectMapper = new ObjectMapper();
        LoginDto loginDto;
        try {
            loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // authenticate 메소드의 파리미터 값이 Authentication를 요구하고 있기 때문에, 해당 하위 클래스로 감싸준다.
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        return customAuthenticationManager.authenticate(authenticationToken);
    }

    // attemptAuthentication 메소드가 완전히 끝난후 , 로그인에 성공한 경우 바로 처리되는 메소드
    // 로그인에 성공했기 때문에, access , refresh token을 만들어줘서 반환한다. 아직까지는 Spring Context Holder에 사용자 정보를 저장하지 않는다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException {

        String access_token = jwtService.createAccessToken(request, authentication, "secret", 10);
        String refresh_token = jwtService.createRefreshToken(request, authentication, "secret", 60);


        Map<String , String> tokens = new HashMap<>();
        tokens.put("access_token" , access_token);
        tokens.put("refresh_token" , refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), tokens); // that's going to return everything in the body
    }
}
