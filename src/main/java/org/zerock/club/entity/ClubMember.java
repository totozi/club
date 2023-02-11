package org.zerock.club.entity;

import lombok.*;

import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import java.util.HashSet;
import java.util.Set;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@ToString
public class ClubMember extends BaseEntity{

    @Id
    private String email;

    private String password;

    private String name;

    private boolean fromSocial;

    @ElementCollection(fetch = FetchType.LAZY) // 지연로딩 LAZY를 사용해서 프록시로 조회하는 방법
    @Builder.Default // 기본값 설정을 위한 어노테이션
    private Set<ClubMemberRole> roleSet = new HashSet<>();

    public void addMemberRole(ClubMemberRole clubMemberRole) {
        roleSet.add(clubMemberRole);
    }



}
