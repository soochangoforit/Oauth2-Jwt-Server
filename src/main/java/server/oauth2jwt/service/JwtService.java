package server.oauth2jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import server.oauth2jwt.domain.AppUser;
import server.oauth2jwt.domain.AppUserWithRole;
import server.oauth2jwt.domain.Role;
import server.oauth2jwt.security.PrincipalDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final AppUserService appUserService;


    // 새롭게 로그인할때 해당 메소드를 거쳐서 token 샹성
    // 나머지 경우는 모두, access랑 refresh token을 생성하는 메소드를 거쳐서 token을 반환한다.
    public String createAccessToken(HttpServletRequest request, Authentication authentication , String algorithmKey , Integer validMinutes){

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        AppUser user = principalDetails.getAppUser();

        Algorithm algorithm = Algorithm.HMAC256(algorithmKey.getBytes());

        String access_token = JWT.create()
                .withSubject(user.getId().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutes * 60 * 1000))
                .withIssuer(request.getRequestURI().toString())
                .withClaim("username" , user.getUsername())
                .withClaim("roles" ,  principalDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);


        return access_token;
    }


    // 새롭게 로그인할때 해당 메소드를 거쳐서 token 샹성
    // 나머지 경우는 모두, access랑 refresh token을 생성하는 메소드를 거쳐서 token을 반환한다.
    public String createRefreshToken(HttpServletRequest request, Authentication authentication , String algorithmKey , Integer validMinutes){

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        AppUser user = principalDetails.getAppUser();

        Algorithm algorithm = Algorithm.HMAC256(algorithmKey.getBytes());

        String refresh_token = JWT.create()
                .withSubject(user.getId().toString())
                .withClaim("username" , user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutes * 60 * 1000))
                .withIssuer(request.getRequestURI().toString())
                .sign(algorithm);

        return refresh_token;

    }


    // client으로부터 refresh token을 받아서 새로운 access , refresh token을 반환한다.
    // refresh token으로 access , refresh token을 새로 요청할때는 해당 refresh token이 정말 올바른 사용자로부터
    // 온것인지 알아야 하기 때문에 한번 DB로부터 조회 쿼리가 날아가야 한다. AccessToken은 DB조회 쿼리 나가지 X
    // token 내부적으로만 유효한지 판단 -> 따로 추가 조회 쿼리 나가지 않는다. Access Token일 경우
    public Map<String , String> getNewAccessTokenWithRefreshToken(HttpServletRequest request , String authorizationHeader , String algorithmKey , Integer validMinutesForAccessToken , Integer validMinutesForRefreshToken) {

        String refresh_token = authorizationHeader.substring("Bearer ".length());
        Algorithm algorithm = Algorithm.HMAC256(algorithmKey.getBytes());

        JWTVerifier verifier = JWT.require(algorithm).build();

        // todo : refresh token 마저 유효기간이 지난 경우 별도의 error를 내밭어야 한다.
        DecodedJWT decodedJWT = verifier.verify(refresh_token);

        String username = decodedJWT.getClaim("username").asString(); // get the username from the token
        AppUser appUser = appUserService.findAppUserByUsername(username);

        String access_token = JWT.create()
                .withSubject(appUser.getId().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutesForAccessToken * 60 * 1000))
                .withIssuer(request.getRequestURI().toString())
                .withClaim("username", appUser.getUsername())
                .withClaim("roles", appUser.getAppUserWithRoles().stream().map(AppUserWithRole::getRole).map(Role::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        String new_refresh_token = JWT.create()
                .withSubject(appUser.getId().toString()) // subject can be really any String that we want , So that can be like , the user Id or the username or something unique about the user, so that we can identify the user by that specific token
                .withClaim("username" , appUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutesForRefreshToken * 60 * 1000)) // // going to give this more time, give this a week or a day
                .withIssuer(request.getRequestURI().toString()) // we don't need to pass roles in refresh token
                .sign(algorithm);

        Map<String , String> map = new java.util.HashMap<>();
        map.put("access_token" , access_token);
        map.put("refresh_token" , new_refresh_token);

        return map;

    }


}
