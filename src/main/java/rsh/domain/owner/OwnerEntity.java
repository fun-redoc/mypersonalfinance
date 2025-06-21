package rsh.domain.owner;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.springframework.security.core.userdetails.User;
import rsh.user.UserEntity;

import java.util.HashSet;
import java.util.Set;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OwnerEntity {
    @Id
    @SequenceGenerator(name = "owner_seq",
                       sequenceName = "owner_seq",
                       allocationSize = 1,
                       initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "owner_seq")
    Long id;

    // TODO there is a smell beeing dependent on an non-domain entity, how to make it better?
    @PrimaryKeyJoinColumn
    @ManyToMany(fetch = FetchType.LAZY )
    //@JoinTable(
    //        name = "owners_users",
    //        joinColumns = @JoinColumn(name = "owner_id"),
    //        inverseJoinColumns = @JoinColumn(name = "user_id"),
    //        uniqueConstraints = {
    //                @UniqueConstraint(
    //                        columnNames = {"user_id", "owner_id"}
    //                )
    //        }
    //)
    @Cache(usage = CacheConcurrencyStrategy.TRANSACTIONAL)
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private Set<UserEntity> users = new HashSet<>();

    @Column(name = "name", unique = true, nullable = false)
    private String name;

    public OwnerEntity addUser(UserEntity user) {
        users.add(user);
        user.getOwners().add(this);
        return this;
    }
}
