package rsh.domain.account.post;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rsh.domain.account.AccountEntity;

import java.util.List;

public interface PostRepository extends JpaRepository<PostEntity, Long> {
    public List<PostEntity> findPostsByToAccount(AccountEntity accountEntity);
    public List<PostEntity> findPostsByFromAccount(AccountEntity accountEntity);
    public Long countPostsByToAccount(AccountEntity accountEntity);
    public Long countPostsByFromAccount(AccountEntity accountEntity);

    @Query("""
            select new rsh.domain.account.post.PostDto(
                                                p.id,
                                                p.date,
                                                p.fromAccount.id,
                                                p.toAccount.id,
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
    public List<PostDto> findPostsByToAccountAndDepositIsNull(@Param("uid") String userId,
                                                @Param("aid") Long accountId);
}
