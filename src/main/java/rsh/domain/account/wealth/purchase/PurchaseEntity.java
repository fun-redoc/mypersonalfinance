package rsh.domain.account.wealth.purchase;

import jakarta.persistence.*;
import jakarta.persistence.GenerationType.*;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import rsh.domain.account.wealth.WealthEntity;
import rsh.domain.owner.OwnerEntity;

import java.math.BigDecimal;
import java.util.Date;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "purchase")
public class PurchaseEntity {
    @Id
    @SequenceGenerator(name = "purchase_seq", sequenceName = "purchase_seq", initialValue = 1, allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "purchase_seq")
    @Column(name = "id", updatable = false, nullable = false, unique = true)
    private Long id;

    @PrimaryKeyJoinColumn
    @ManyToOne
    private OwnerEntity belongsTo;

    private String bank;

    @ManyToOne
    private WealthEntity wealthEntity;

    @NotNull
    private Long units;

    @NotNull
    @Column(name = "price")
    private BigDecimal pricePerUnit;

    @NotNull
    private Date date;
    private BigDecimal fee;
}
