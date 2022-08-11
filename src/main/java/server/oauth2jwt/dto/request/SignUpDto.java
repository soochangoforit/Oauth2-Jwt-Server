package server.oauth2jwt.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SignUpDto {

    private String name;
    private String username;
    private String password;

}
