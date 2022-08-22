package server.oauth2jwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import server.oauth2jwt.dto.request.SignUpDto;
import server.oauth2jwt.security.PrincipalDetails;
import server.oauth2jwt.service.AppUserService;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final AppUserService appUserService;


    @GetMapping("/")
    public String login() {
        return "loginPage";
    }

    @PostMapping(value = "/signUp" )
    @ResponseBody
    public ResponseEntity<String> signUp(@RequestBody SignUpDto signUpDto) {

        appUserService.signUp(signUpDto);

        return new ResponseEntity<>(signUpDto.getUsername(), org.springframework.http.HttpStatus.OK);
    }


    @GetMapping("/user")
    @ResponseBody
    public void findwho(@AuthenticationPrincipal Long id){

        Long who = id;

        String a = "aa";

    }

}
