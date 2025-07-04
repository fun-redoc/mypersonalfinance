package rsh.domain.owner;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.user.UserEntity;

import java.util.List;
import java.util.Optional;

public interface OwnerRepository extends JpaRepository<OwnerEntity, String> {
    Optional<OwnerEntity> findOwnerByName(String name);
    @Query("""
            select o from OwnerEntity o
            where :u in elements(o.users)
            """)
    List<OwnerEntity> findOwnerByUser(@Param("u") UserEntity userEntity);
}
