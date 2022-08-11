package server.oauth2jwt.security;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import server.oauth2jwt.domain.AppUser;
import server.oauth2jwt.dto.response.AppUserResponseForSecurity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Getter
public class PrincipalDetails implements UserDetails , OAuth2User {

    private AppUser appUser;

    // Oauth2
    private Map<String ,Object> attributes;

    @Autowired
    public PrincipalDetails(AppUser appUser) { // 일반 로그인용 생성자
        this.appUser = appUser;
    }

    // Oauth2
    public PrincipalDetails(AppUser appUser,Map<String, Object> attributes) { // OAuth2 로그인용 생성지
        this.appUser = appUser;
        this.attributes = attributes;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> authorities = new ArrayList<>();

        appUser.getAppUserWithRoles().forEach(appUserWithRole -> {
            authorities.add(new SimpleGrantedAuthority(appUserWithRole.getRole().getAuthority()));
        });
        return authorities;

    }


    // oauth2
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // oauth2
    @Override
    public String getName() {
        return appUser.getName();
    }



    @Override
    public String getPassword() {
        return appUser.getPassword();
    }

    @Override
    public String getUsername() {
        return appUser.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


}
