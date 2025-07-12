package rsh.user;

import jakarta.persistence.*;
import lombok.*;
import rsh.domain.owner.OwnerEntity;

import java.util.Set;

@Entity(name = "User")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users")
public class UserEntity {
    @Id
    @Column(name="id", updatable = false,unique = true,nullable = false)
    // id is not set automatically, it is expected that id stems from the registration credentials
    private String id;

    @Column(name="user_name", unique = true, nullable = false)
    private String username;

    @Column(name="email", unique = true, nullable = false)
    private String email;

    @Lob @Column
    private String credentials;

    @Lob @Column
    private String response;

    @Lob @Column
    private String attestationObject;
    @Lob @Column
    private String authenticatorData;
    @Lob @Column
    private String clientDataJSON;
    @Lob @Column // (unique = true) unique does not work for LARGE OBJECT, so I would need to introduce a unique hash column
    private String publicKey;
    @Column(unique = true)
    private String publicKeyHashSHA256;
    @Lob @Column
    private Integer publicKeyAlgorithm;

    @Lob @Column
    private Set<String> transports;

    @Column(name="challenge")
    private  String challenge;

    @PrimaryKeyJoinColumn
    @ManyToMany(mappedBy = "users", fetch = FetchType.LAZY)
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private Set<OwnerEntity> owners;

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email == null ? "-": email + '\'' +
                '}';
    }
}