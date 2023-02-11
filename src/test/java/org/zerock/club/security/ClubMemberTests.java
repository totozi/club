package org.zerock.club.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.zerock.club.entity.ClubMember;
import org.zerock.club.entity.ClubMemberRole;
import org.zerock.club.repository.ClubMemberRepository;

import java.util.HashSet;
import java.util.Optional;
import java.util.stream.IntStream;

@SpringBootTest
public class ClubMemberTests {

    @Autowired
    private ClubMemberRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void insertDummies() {

        // 1 ~ 80 까지는 USER
        // 81 ~ 90 까지는 USER, MANAGER
        // 91 ~ 100 까지는 USER, MANAGER, ADMIN

        System.out.println(passwordEncoder.getClass());

        IntStream.rangeClosed(1,100).forEach(i -> {
            ClubMember clubMember = ClubMember.builder()
                    .email("user" + i + "@zerock.org")
                    .name("사용자" + i)
                    .fromSocial(false)
                    .roleSet(new HashSet<ClubMemberRole>())
                    .password( passwordEncoder.encode("1234"))
                    .build();

            // default role
            clubMember.addMemberRole(ClubMemberRole.USER);

            if(i > 80) {
                clubMember.addMemberRole(ClubMemberRole.MANAGER);
            }
            if(i > 90) {
                clubMember.addMemberRole(ClubMemberRole.ADMIN);
            }

            repository.save(clubMember);
        });
    }

    @Test
    public void testRead() {
        Optional<ClubMember> result = repository.findByEmail("user95@zerock.org", false);

        ClubMember clubMember =result.get();

        System.out.println(clubMember);

        String password = "1234";

        String enPw = passwordEncoder.encode(password);

        System.out.println("enPw : " + enPw);

        System.out.println("clubMember.getPassword() : " + clubMember.getPassword());

        boolean matchResult = passwordEncoder.matches(password, clubMember.getPassword());

        System.out.println("matchResult : " + matchResult);


    }

}
