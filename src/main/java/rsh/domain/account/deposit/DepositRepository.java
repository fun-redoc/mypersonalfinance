package rsh.domain.account.deposit;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.format.annotation.DateTimeFormat;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.deposit.interest.FlatInterestEntity;
import rsh.domain.account.deposit.interest.FlatPlusBonusAtEndInterestEntity;
import rsh.domain.account.post.PostDto;
import rsh.user.UserEntity;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public interface DepositRepository extends JpaRepository<DepositEntity, Long> {

    record AccountListDTO(Long id, String name, String bank){}

    record PostingDto(Long id, Date date, BigDecimal amount){
        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (other == null || getClass() != other.getClass())
                return false;
            return  this.id == ((PostingDto)other).id();
        }
        @Override
        public int hashCode() {
            return this.id.hashCode();
        }
    }

    @Data
    @AllArgsConstructor
    class TagDto {
        Long id; // can be null, if recently entered
        @NotNull
        String name;
    }

    public Long countDepositsByAccount(AccountEntity accountEntity);

    @Query("""
            select d from DepositEntity d where :t in elements(d.tags)
            """)
    public List<DepositEntity> findByTag(@Param("t") TagEntity tagEntity);

    @Query("""
            select sum(p.amount)
              from PostEntity p
              inner join DepositEntity d on d = p.deposit
              where d = :d
            """)
    public Optional<BigDecimal> totalAmountOf(@Param("d") DepositEntity depositEntity);


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
    //        where :u in elements(o.users)
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
            where :u in elements(o.users)
            """)
    public List<DepositListDto> findDepositsForUser(@Param("u")UserEntity userEntity);

    @Query("""
            select new rsh.domain.account.deposit.DepositRepository$TagDto(t.id, t.name)
            from TagEntity t
            inner join DepositEntity d on d.id = :did
            """)
    public List<TagDto> getTagsByDepositId(@Param("did") Long depositId);
}
