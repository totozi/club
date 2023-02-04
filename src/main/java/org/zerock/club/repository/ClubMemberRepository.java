package org.zerock.club.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.zerock.club.entity.ClubMember;

import java.util.Optional;

public interface ClubMemberRepository extends JpaRepository<ClubMember, String> {

    @EntityGraph(attributePaths = {"roleSet"}, type = EntityGraph.EntityGraphType.LOAD)
    @Query("SELECT M\n" +
            "  FROM ClubMember M\n" +
            " WHERE M.fromSocial = :social\n" +
            "   AND M.email = :email")
    Optional<ClubMember> findByEmail(String email, boolean social);


}
