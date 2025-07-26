package rsh.domain.account.deposit;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.account.AccountEntity;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

public interface DepositRepository extends JpaRepository<DepositEntity, Long> {
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
}
