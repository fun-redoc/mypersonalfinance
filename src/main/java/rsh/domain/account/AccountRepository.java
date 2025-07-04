package rsh.domain.account;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.account.deposit.DepositEntity;
import rsh.domain.owner.OwnerEntity;
import rsh.user.UserEntity;
import rsh.web.AppController;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public interface AccountRepository extends JpaRepository<AccountEntity, Long> {
    public interface AccountsBaseData {
        Long getId();
        rsh.domain.account.AccountEntity.AccountType getAccountType();
        String getName();
        String getIban();
        String getBank();
        Date getDateCreated();
        Date getDateClosed();
        Long getOwnerId();
        String getOwnerName();
        BigDecimal getBalance();
    }

    @Query("""
            select a.id as id, a.accountType as accountType, a.name as name, a.iban as iban, a.bank as bank, a.dateCreated as dateCreated, a.dateClosed as dateClosed,
                    o.id as ownerId, o.name as ownerName
                from AccountEntity a
                    inner join a.belongsTo o
                    inner join o.users u
                where u = :u
            """)
    List<AccountsBaseData> findBaseByUser(@Param("u") UserEntity userEntity);


    @Query("""
            select a from AccountEntity a
                inner join a.belongsTo o
                inner join o.users u
                where u = :u
            """)
    List<AccountEntity> findByUser(@Param("u")UserEntity userEntity);

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
            select a.id as id, a.accountType as accountType, a.name as name, a.iban as iban, a.bank as bank, a.dateCreated as dateCreated, a.dateClosed as dateClosed,
                    o.id as ownerId, o.name as ownerName,
                    lateral (select (sum(movement.kred) - sum(movement.deb))
                                from (select amount as kred, 0 as deb
                                        from PostEntity where toAccount = a
                                        union all
                                      select 0 as kred, amount as deb
                                        from PostEntity where fromAccount = a) as movement
                    ) as balance
                from AccountEntity a
                    inner join a.belongsTo o
                    inner join o.users u
                where u = :u
            """)
    List<AccountsBaseData> findBaseWithBalanceByUser(@Param("u") UserEntity userEntity);

    @Query("""
            select d from DepositEntity d
                    left join fetch d.posts 
                    left join fetch d.tags
                where d.account = :a
           """)
    List<DepositEntity> allDepositsWithPostings(@Param("a") AccountEntity accountEntity);
}