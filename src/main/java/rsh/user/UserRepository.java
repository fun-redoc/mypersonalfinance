package rsh.user;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, String> {
    Optional<UserEntity> findUserByUsername(String username);
    @Query("""
            select new rsh.user.UserBaseDto(u.id, u.username, u.email)
              from rsh.user.UserEntity u
            """)
    // @Cacheable
    List<UserBaseDto> findAllUsersWithBaseDto();
}
