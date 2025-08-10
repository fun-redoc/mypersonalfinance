package rsh.domain.owner;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.user.UserEntity;

import java.util.List;
import java.util.Optional;

public interface OwnerRepository extends JpaRepository<OwnerEntity, Long> {
    List<OwnerEntity> findByAdmin(UserEntity userEntity);
    Optional<OwnerEntity> findOwnerByName(String name);

    @Query("""
            select o
                from OwnerEntity o
                left join fetch o.users
                where o.id = :oid
            """)
        // TODO repolace by an appropriate Dto, User Objects are to beeg and consist of to critical data
    Optional<OwnerEntity> findOwnerByIdFetchingUsers(@Param("oid") Long oid);

    @Query("""
            select o
                from OwnerEntity o
                left join fetch o.users
                where o.admin = :admin
            """)
    // TODO repolace by an appropriate Dto, User Objects are to beeg and consist of to critical data
    List<OwnerEntity> findOwnersByAdminFetchingUsers(@Param("admin") UserEntity userEntity);

    @Query("""
            select o from OwnerEntity o
            where :first in elements(o.users)
            """)
    List<OwnerEntity> findOwnerByUser(@Param("first") UserEntity userEntity);
}
