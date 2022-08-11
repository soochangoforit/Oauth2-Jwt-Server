package server.oauth2jwt.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import server.oauth2jwt.domain.AppUser;

@Getter
@AllArgsConstructor
public class AppUserResponse {

    private Long id;

    private String name;

    public AppUserResponse(AppUser appUser) {
        this.id = appUser.getId();
        this.name = appUser.getName();
    }

}
