package server.oauth2jwt.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;


@Entity
@Getter
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @Column(unique = true)
    private String username;

    private String password;

    private String picture;

    @OneToMany(mappedBy = "appUser", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private Collection<AppUserWithRole> appUserWithRoles = new ArrayList<>();

    public AppUser() {
    }

    @Builder
    public AppUser( String name, String username, String password,String picture , Collection<AppUserWithRole> appUserWithRoles) {
        this.name = name;
        this.username = username;
        this.password = password;
        this.picture = picture;
        this.appUserWithRoles = appUserWithRoles;
    }

    public void setAppUserWithRoles(Collection<AppUserWithRole> appUserWithRoles) {
        this.appUserWithRoles = appUserWithRoles;
    }
}
