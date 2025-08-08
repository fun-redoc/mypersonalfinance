package rsh.domain.account.deposit;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import rsh.domain.owner.OwnerEntity;

import java.util.Set;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tags",
       indexes = {  @Index(name = "idxTagBelongs",
                               unique = false,
                               columnList = "belongs_to_id"
                       ),
                    @Index(name = "idxTagBelongsToAndName",
                                     unique = true,
                                     columnList = "belongs_to_id, name"
                                    )
                             }
      )
@EqualsAndHashCode(exclude = { "deposits"}) // This,
@ToString(exclude = { "deposits"})
public class TagEntity {
    @Id
    @SequenceGenerator(name = "tag_seq", sequenceName = "tag_seq", initialValue = 1, allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "tag_seq")
    @Column(name = "id", updatable = false, nullable = false, unique = true)
    private Long id;

    @PrimaryKeyJoinColumn
    @ManyToOne
    private OwnerEntity belongsTo;

    @NotNull
    @Column(unique = true)
    private String name;

    @ManyToMany(mappedBy = "tags", fetch = FetchType.LAZY)
    private Set<DepositEntity> deposits;// = new HashSet<>();

    //public Tag() {
    //}
    //public Tag(String name) {
    //    this.name = name;
    //}
    //public Tag(Long id, String name) {
    //    this.id = id;
    //    this.name = name;
    //}

    public TagEntity addTag(DepositEntity deposit) {
        var success = deposits.add(deposit);
        if(success) deposit.getTags().add(this);
        return this;
    }

    public TagEntity removeTag(DepositEntity deposit) {
        var success = deposits.remove(deposit);
        if(success) deposit.getTags().remove(this);
        return this;
    }

    //@Override
    //public String toString() {
    //    return name;
    //}
    //@Override
    //public boolean equals(Object o) {
    //    if (this == o) return true;
    //    if (o == null || getClass() != o.getClass()) return false;
    //    Tag tag = (Tag) o;
    //    return Objects.equals(name, tag.name);
    //}

    //@Override
    //public int hashCode() {
    //    return Objects.hash(name);
    //}

}
