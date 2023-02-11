package org.zerock.club.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.zerock.club.entity.ClubMember;
import org.zerock.club.entity.ClubMemberRole;
import org.zerock.club.repository.ClubMemberRepository;
import org.zerock.club.security.dto.ClubAuthMemberDTO;

import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service
@RequiredArgsConstructor
public class ClubOAuth2UserDetailsService extends DefaultOAuth2UserService {

    private final ClubMemberRepository repository;

    private final PasswordEncoder passwordEncoder;

    /*
        파라미터는  OAuth2UserRequest
        리턴 타입은 OAuth2User 이므로 기존의 로그인 처리에 사용하던 것과 달라 
        이를 변환해서 처리해야 브라우저와 컨트롤러의 결과를 일반적인 로그인과 동일하게 사용 가능
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        log.info("-------------------------------------------------");
        log.info("userRequest : " + userRequest);

        // 사용자 이메일 추출

        String clientName = userRequest.getClientRegistration().getClientName();

        log.info("clientName : " + clientName); // Google
        log.info(userRequest.getAdditionalParameters());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        log.info("==============================================");
        oAuth2User.getAttributes().forEach((k, v) -> {
            log.info(k + " : " + v);
        });
        // sub, picture, email, email_verified 출력

        String email = null;

        if(clientName.equals("Google")) {
            email = oAuth2User.getAttribute("email");
        }

        log.info("EMAIL : " + email);

        ClubMember member = saveSocialMember(email);

        ClubAuthMemberDTO clubAuthMemberDTO = new ClubAuthMemberDTO(
                member.getEmail(),
                member.getPassword(),
                true, // fromSocial
                member.getRoleSet().stream().map( role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                        .collect(Collectors.toList()),
                oAuth2User.getAttributes()
        );

        clubAuthMemberDTO.setName(member.getName());

        return clubAuthMemberDTO;
        // saveSocialMember() 의 결과를 나오는 ClubMember를 활용해서 DTO 구성
        // OAuth2User의 모든 데이터는 ClubAuthMemberDTO의 내부로 전달해서 필요한 순간에 사용 가능
    }

    private ClubMember saveSocialMember(String email) {
        // 기존 동일 이메일로 가입한 회원 있으면 조회만
        Optional<ClubMember> result = repository.findByEmail(email, true);

        if(result.isPresent()) {
            return result.get();
        }

        // 없으면 회원 추가 패스워드는 1111
        // 임시로 이렇게 한 것..
        ClubMember clubMember = ClubMember.builder().email(email)
                .name(email)
                .password(passwordEncoder.encode("1111"))
                .fromSocial(true)
                .build();

        clubMember.addMemberRole(ClubMemberRole.USER);

        repository.save(clubMember);

        return clubMember;
    }

}
