package rsh.domain.aggregates;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.AccountRepository;
import rsh.domain.account.post.PostRepository;

import java.math.BigDecimal;

@Service
public class Balance {
    @Autowired
    PostRepository postRepository;
    @Autowired
    AccountRepository accountRepository;

    public BigDecimal balance_slow(AccountEntity accountEntity) {
        //var toPosts = postService.findAllToPosts(accountEntity);
        //var fromPosts = postService.findAllFromPosts(accountEntity);
        var toPosts = postRepository.findPostsByToAccount(accountEntity);
        var fromPosts = postRepository.findPostsByFromAccount(accountEntity);
        BigDecimal toAmount = toPosts.stream()
                .reduce(BigDecimal.ZERO,
                        (acc, x)-> {return acc.add(x.getAmount());},
                        BigDecimal::add);
        BigDecimal fromAmount = fromPosts.stream()
                .reduce(BigDecimal.ZERO,
                        (acc, x)-> {return acc.add(x.getAmount());},
                        BigDecimal::add);
        return toAmount.subtract(fromAmount);
    }

    public BigDecimal balance(AccountEntity accountEntity) {
        return accountRepository.balance(accountEntity).orElse(BigDecimal.ZERO);
    }
}
