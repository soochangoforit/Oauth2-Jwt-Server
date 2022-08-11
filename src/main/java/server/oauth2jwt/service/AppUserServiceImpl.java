package server.oauth2jwt.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import server.oauth2jwt.domain.AppUser;
import server.oauth2jwt.domain.AppUserWithRole;
import server.oauth2jwt.domain.Role;
import server.oauth2jwt.dto.request.SignUpDto;
import server.oauth2jwt.dto.response.AppUserResponse;
import server.oauth2jwt.repository.AppUserRepository;
import server.oauth2jwt.security.PrincipalDetails;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AppUserServiceImpl implements AppUserService {

    private final AppUserRepository appUserRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;




    // manager에서 사용
    @Override
    public AppUserResponse findResponseDtoByUsername(String username) {

        AppUser appUser = appUserRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));

        AppUserResponse appUserResponse = new AppUserResponse(appUser);

        return appUserResponse;
    }

    @Override
    public AppUser findAppUserByUsername(String username) {
        AppUser appUser = appUserRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        return appUser;
    }

    @Override
    @Transactional
    public void signUp(SignUpDto signUpDto) {

        String encodePw = bCryptPasswordEncoder.encode(signUpDto.getPassword());

        AppUser appUser = AppUser.builder()
                .name(signUpDto.getName())
                .username(signUpDto.getUsername())
                .password(encodePw)
                .build();

        AppUserWithRole role1 = AppUserWithRole.builder()
                .appUser(appUser)
                .role(Role.ROLE_USER)
                .build();

        AppUserWithRole role2 = AppUserWithRole.builder()
                .appUser(appUser)
                .role(Role.ROLE_MANAGER)
                .build();

        // make arraylist of role
        List<AppUserWithRole> roles = new ArrayList<>(List.of(role1, role2));

        appUser.setAppUserWithRoles(roles);

        AppUser saved = appUserRepository.save(appUser);


    }

}
