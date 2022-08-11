package server.oauth2jwt.service;

import server.oauth2jwt.domain.AppUser;
import server.oauth2jwt.dto.request.SignUpDto;
import server.oauth2jwt.dto.response.AppUserResponse;

public interface AppUserService {

    AppUserResponse findResponseDtoByUsername(String username);

    AppUser findAppUserByUsername(String username);

    void signUp(SignUpDto signUpDto);

}
