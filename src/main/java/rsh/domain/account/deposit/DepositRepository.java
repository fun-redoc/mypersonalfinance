package rsh.domain.account.deposit;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.account.AccountEntity;
import rsh.user.UserEntity;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

public interface DepositRepository extends JpaRepository<DepositEntity, Long> {

    record AccountListDTO(Long id, String name, String bank){}

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    class TagDto {
        Long id; // can be null, if recently entered
        @NotNull
        String name;
    }

    Long countDepositsByAccount(AccountEntity accountEntity);

    @Query("""
            select d from DepositEntity d where :t in elements(d.tags)
            """)
    List<DepositEntity> findByTag(@Param("t") TagEntity tagEntity);

    @Query("""
            select sum(p.amount)
              from PostEntity p
              inner join DepositEntity d on d = p.deposit
              where d = :d
            """)
    Optional<BigDecimal> totalAmountOf(@Param("d") DepositEntity depositEntity);


    //@Query("""
    //        select new rsh.domain.account.deposit.DepositListDto(
    //                         d.id,
    //                         d.name,
    //                         d.account.id,
    //                         d.account.bank,
    //                         d.begin,
    //                         d.due,
    //                         d.interest.id,
    //                 (COALESCE((select sum(p.amount) from PostEntity p where p in elements(d.posts)),0)),
    //                         null,
    //                         d.tags
    //                        )
    //        from DepositEntity d
    //            inner join OwnerEntity o on o = d.belongsTo
    //            left join fetch d.tags
    //        where :first in elements(o.users)
    //        """)
    @Query("""
            select new rsh.domain.account.deposit.DepositListDto(
                             d.id,
                             d.name,
                             d.account.id,
                             d.account.bank,
                             d.begin,
                             d.due,
                             d.interest.id,
                     (COALESCE((select sum(p.amount) from PostEntity p where p in elements(d.posts)),0)),
                             null,
                             null
                            )
            from DepositEntity d
                inner join OwnerEntity o on o = d.belongsTo
            where :first in elements(o.users)
            """)
    List<DepositListDto> findDepositsForUser(@Param("first") UserEntity userEntity);

    @Query("""
            select new rsh.domain.account.deposit.DepositRepository$TagDto(t.id, t.name)
            from TagEntity t
            inner join DepositEntity d on d.id = :did
            """)
    List<TagDto> getTagsByDepositId(@Param("did") Long depositId);
}
