package org.zerock.club.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.zerock.club.entity.ClubMember;
import org.zerock.club.repository.ClubMemberRepository;
import org.zerock.club.security.dto.ClubAuthMemberDTO;

import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service
@RequiredArgsConstructor
public class ClubUserDetailsService implements UserDetailsService {
    // 이 클래스가 Bean으로 등록되면 자동으로 스프링 시큐리티에서 UserDetailsService로 인식함 
    // -> InMemoryUserDetailsManager객체 더 이상 사용하면 안되므로 주석처리

    // 주입 후 @RequiredArgsConstructor 처리
    private final ClubMemberRepository clubMemberRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("ClubUserDetailsService loadUserByUsername : " + username);

        Optional<ClubMember> result = clubMemberRepository.findByEmail(username, true); // username == email 임

        // System.out.println("result : " + result.get());

        if(!result.isPresent()) {
            throw new UsernameNotFoundException("Check Email or Social");
        }

        ClubMember clubMember = result.get();

        log.info("------------------------------------");
        log.info(clubMember);

        // ClubMember 를 UserDetails 타입으로 처리하기 위해서 ClubAuthMemberDTO 타입으로 변환
        ClubAuthMemberDTO clubAuthMemberDTO = new ClubAuthMemberDTO(
                clubMember.getEmail(),
                clubMember.getPassword(),
                clubMember.isFromSocial(),
                clubMember.getRoleSet().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name())).collect(Collectors.toSet())
                // ClubMemberRole 은 스프링 시큐리티에서 사용하는 SimpleGrantedAuthority로 변환
                // 이때 "ROLE_" 라는 접두어를 추가해서 사용
        );

        clubAuthMemberDTO.setName(clubMember.getName());
        clubAuthMemberDTO.setFromSocial(clubMember.isFromSocial());

        return clubAuthMemberDTO;
    }




}
