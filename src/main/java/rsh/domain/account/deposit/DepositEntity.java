package rsh.domain.account.deposit;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import rsh.domain.account.AccountEntity;
import rsh.domain.owner.OwnerEntity;
import rsh.domain.account.post.PostEntity;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "deposits")
@EqualsAndHashCode(exclude = { "posts"}) // This,
@ToString(exclude = { "posts"})
public class DepositEntity {
    @Id
    @SequenceGenerator(name = "deposit_seq", sequenceName = "deposit_seq", initialValue = 1, allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "deposit_seq")
    @Column(name = "id", updatable = false, nullable = false, unique = true)
    private Long id;

    @PrimaryKeyJoinColumn
    @ManyToOne
    private OwnerEntity belongsTo;

    private String name;

    @PrimaryKeyJoinColumn
    @ManyToOne
    private AccountEntity account;

    @NotNull
    private Date begin;
    private Date due;


    @PrimaryKeyJoinColumn
    @ManyToOne(cascade = CascadeType.ALL)
    private InterestEntity interest;

    @OneToMany(mappedBy = "deposit",  fetch = FetchType.LAZY, cascade = CascadeType.DETACH)
    //@OneToMany(fetch = FetchType.LAZY)
    private List<PostEntity> posts;

    //@ManyToMany(fetch = FetchType.LAZY, cascade = { CascadeType.ALL })
    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.DETACH})
    @JoinTable(
            name = "deposit_tags",
            joinColumns = @JoinColumn(name = "deposit_id"),
            inverseJoinColumns = @JoinColumn(name = "tag_id"),
            uniqueConstraints = {
                    @UniqueConstraint(
                            columnNames = {"deposit_id", "tag_id"}
                    )
            }
    )
    private Set<TagEntity> tags;// = new HashSet<>();

    public DepositEntity addTag(TagEntity tag) {
        if(tags == null) setTags(new HashSet<>());
        var success = tags.add(tag);
        if(success) tag.getDeposits().add(this);
        return this;
    }

    public DepositEntity removeTag(TagEntity tag) {
        var success = tags.remove(tag);
        if(success) tag.getDeposits().remove(this);
        return this;
    }

    public DepositEntity addPost(PostEntity post) {
        if(this.getAccount().getId() != post.getToAccount().getId()) {
            throw new IllegalStateException(String.format("the to-account of the post (%d) should match the deposit account (%d)", post.getToAccount().getId(), this.getAccount().getId()));
        }
        var success = posts.add(post);
        if(success) post.setDeposit(this);
        return this;
    }

    public DepositEntity removePost(PostEntity post) {
        var success = posts.remove(post);
        if(success) post.setDeposit(null);
        return this;
    }
}

