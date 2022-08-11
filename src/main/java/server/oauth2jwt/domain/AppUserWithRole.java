package server.oauth2jwt.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity @Getter @NoArgsConstructor
public class AppUserWithRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "app_user_id", foreignKey = @ForeignKey(name = "fk_app_user_id"))
    private AppUser appUser;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder
    public AppUserWithRole(AppUser appUser, Role role) {
        this.appUser = appUser;
        this.role = role;
    }


    public void linkAppUser(AppUser appUser) {
        this.appUser = appUser;
        appUser.getAppUserWithRoles().add(this);
    }
}
