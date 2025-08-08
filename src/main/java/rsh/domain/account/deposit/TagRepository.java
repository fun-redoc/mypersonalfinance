package rsh.domain.account.deposit;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.owner.OwnerEntity;

import java.util.List;
import java.util.Optional;

public interface TagRepository extends JpaRepository<TagEntity, Long> {
    @Query("""
            select new rsh.domain.account.deposit.TagDto(
                t.id,
                t.name
            )
            from TagEntity t
                inner join OwnerEntity o on o = t.belongsTo
                inner join o.users as u
            where
                :uid = u.id
             and :n = t.name
            """)
    Optional<TagDto> findTagByNameAndOwnerUser(@Param("n") String name, @Param("uid") String userId);
    @Query("""
            select new rsh.domain.account.deposit.TagDto(
                t.id,
                t.name
            )
            from TagEntity t
                inner join OwnerEntity o on o = t.belongsTo
                inner join o.users as u
            where
                :uid = u.id
            """)
    List<TagDto> finaAllTagsByOwnerUser(@Param("uid") String userId);
    List<TagEntity> findAllByBelongsToAndName(OwnerEntity belongsTo, String Name);
    List<TagEntity> findAllByBelongsTo(OwnerEntity belongsTo);
}
