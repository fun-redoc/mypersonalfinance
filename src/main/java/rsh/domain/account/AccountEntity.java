package rsh.domain.account;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import rsh.domain.owner.OwnerEntity;

import java.util.Date;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name="account",
        uniqueConstraints =
        @UniqueConstraint(  name = "account_iban_unique_constr",
                columnNames = {"iban", "account-type"}
        ),
        indexes = {@Index(name = "idx_iban+type", unique = true, columnList = "iban,account-type"),
        @Index(name = "idx_bank", unique = false, columnList = "bank")}
)
public class AccountEntity {
    public enum AccountType{BANK,WALLET,INCOME,SPENDING}
    @Id
    @SequenceGenerator(name = "account_seq",
            sequenceName = "account_seq",
            allocationSize = 1
    )
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "account_seq")
    @Column(name="id", updatable = false,unique = true,nullable = false)
    private Long id;

    @PrimaryKeyJoinColumn
    @ManyToOne(fetch = FetchType.LAZY)
    private OwnerEntity belongsTo;

    @Column(name="account-type", updatable = false, nullable = false)
    @Enumerated(EnumType.STRING)
    private AccountType accountType;

    @Column(name="name", nullable = false, columnDefinition = "TEXT")
    private String name;

    @Column(name="iban", nullable = false) // see table annotation for unique constraint with name
    String iban; // iban is optional

    @Column(name="bank")
    String bank;

    @Column(name="date-created", nullable = false)
    private Date dateCreated;

    @Column(name="date-closed")
    private Date dateClosed;

}

