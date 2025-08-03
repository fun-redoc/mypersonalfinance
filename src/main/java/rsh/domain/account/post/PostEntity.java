package rsh.domain.account.post;

import jakarta.persistence.*;
import lombok.*;
import rsh.domain.account.AccountEntity;
import rsh.domain.account.deposit.DepositEntity;
import rsh.domain.owner.OwnerEntity;

import java.math.BigDecimal;
import java.util.Date;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name="post",
        indexes = {@Index(name = "idx_from", unique = false, columnList = "from-account-id"),
                @Index(name = "idx_to", unique = false, columnList = "to-account-id"),
                @Index(name = "idx_from_to", unique = false, columnList = "from-account-id,to-account-id") }
)
public class PostEntity {
    @Id
    @SequenceGenerator(name = "post_seq", sequenceName = "post_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "post_seq")
    @Column(name = "id", updatable = false, unique = true, nullable = false)
    private Long id;

    @Column(name = "name", nullable = false)
    private String name;

//    @PrimaryKeyJoinColumn
//    @ManyToOne
//    private OwnerEntity belongsTo;

    @Column(name = "date-created", nullable = false )
    private Date date;

    @PrimaryKeyJoinColumn
    @ManyToOne
    @JoinColumn(name = "from-account-id")
    private AccountEntity fromAccount;

    @PrimaryKeyJoinColumn
    @ManyToOne
    @JoinColumn(name = "to-account-id")
    private AccountEntity toAccount;

    @Column(name="amount", nullable = false, precision = 13, scale = 2)
    private BigDecimal amount;

    @ManyToOne
    @JoinColumn(name = "deposit_id")
    private DepositEntity deposit; // some post will belong to deposits (but not all)
}
