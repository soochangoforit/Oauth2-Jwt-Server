package server.oauth2jwt.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import server.oauth2jwt.domain.AppUserWithRole;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

@Getter @NoArgsConstructor
public class AppUserResponseForSecurity implements Serializable {

    private Long id;
    private String name;
    private String username;
    private String password;

    private Collection<AppUserWithRole> roles = new ArrayList<>();

    @Builder
    public AppUserResponseForSecurity(Long id, String name, String username, String password, Collection<AppUserWithRole> roles) {
        this.id = id;
        this.name = name;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

}
