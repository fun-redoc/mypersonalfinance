package rsh.domain.account;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.account.deposit.DepositEntity;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

public interface AccountRepository extends JpaRepository<AccountEntity, Long> {
    @Query("SELECT a FROM AccountEntity a LEFT JOIN FETCH a.belongsTo b LEFT JOIN FETCH b.users")
    List<AccountEntity> findWithOwnerWithUserBy();

    Optional<AccountEntity> findByIbanAndAccountType(String iban, AccountEntity.AccountType accountType);

    @Query("select (sum(kred) - sum(deb)) from (" +
            "select amount as kred, 0 as deb " +
                "from PostEntity where toAccount = :account " +
            "union all " +
            "select 0 as kred, amount as deb " +
                "from PostEntity where fromAccount = :account " +
            ") as movements"
    )
    Optional<BigDecimal> balance(@Param("account") AccountEntity account);

    @Query("""
            select d from DepositEntity d
                    left join fetch d.posts 
                    left join fetch d.tags
                where d.account = :a
           """)
    List<DepositEntity> allDepositsWithPostings(@Param("a") AccountEntity accountEntity);
}