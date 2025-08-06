package rsh.domain.account.post;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.account.AccountEntity;

import java.util.List;

public interface PostRepository extends JpaRepository<PostEntity, Long> {
    List<PostEntity> findPostsByToAccount(AccountEntity accountEntity);
    List<PostEntity> findPostsByFromAccount(AccountEntity accountEntity);
    Long countPostsByToAccount(AccountEntity accountEntity);
    Long countPostsByFromAccount(AccountEntity accountEntity);

    @Query("""
            select new rsh.domain.account.post.PostDto(
                                                p.id,
                                                p.name,
                                                p.date,
                                                p.fromAccount.id,
                                                p.fromAccount.name,
                                                p.toAccount.id,
                                                p.toAccount.name,
                                                p.amount,
                                                null)
            from PostEntity p
                inner join p.toAccount.belongsTo as o
                inner join o.users as u
            where
                p.toAccount.id = :aid
            and :uid = u.id
            and p.deposit is null
            """)
    List<PostDto> findPostsByToAccountAndDepositIsNull(@Param("uid") String userId,
                                                       @Param("aid") Long accountId);

    @Query("""
            select new rsh.domain.account.post.PostDto(
                                                p.id,
                                                p.name,
                                                p.date,
                                                p.fromAccount.id,
                                                p.fromAccount.name,
                                                p.toAccount.id,
                                                p.toAccount.name,
                                                p.amount,
                                                p.deposit.id)
            from PostEntity p
                inner join p.toAccount.belongsTo as o
                inner join o.users as u
            where
                :uid = u.id
            """)
    List<PostDto> findPostsByUserId(@Param("uid") String userId);
}
