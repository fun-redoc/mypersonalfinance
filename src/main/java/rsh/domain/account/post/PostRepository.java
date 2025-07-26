package rsh.domain.account.post;

import org.springframework.data.jpa.repository.JpaRepository;
import rsh.domain.account.AccountEntity;

import java.util.List;

public interface PostRepository extends JpaRepository<PostEntity, Long> {
    public List<PostEntity> findPostsByToAccount(AccountEntity accountEntity);
    public List<PostEntity> findPostsByFromAccount(AccountEntity accountEntity);
    public Long countPostsByToAccount(AccountEntity accountEntity);
    public Long countPostsByFromAccount(AccountEntity accountEntity);
}
