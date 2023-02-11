package org.zerock.club.security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

@Log4j2
@Getter
@Setter
@ToString
public class ClubAuthMemberDTO extends User implements OAuth2User { // User 클래스 상속해서 User 클래스 생성자 호출
    // 엔티티 클래스와 DTO 클래스 별도로 구성했듯  ClubAuthMemberDTO가 그런 역할을 한다
    // DTO 역할과 스프링 시큐리티에서 인가/인증 작업에 사용 가능

    // OAuth2User의 인터페이스를 구현해서 Mapㅇ타입으로 모든 인증결과를 attributes 이름으로 가지고 있으니
    // getAttributes라는 메서드를 오버라이드해서 attr 을 반환하게 한다

    private String email;

    private String name;

    private String password;

    private boolean fromSocial;

    private Map<String, Object> attr;

    public ClubAuthMemberDTO(String username,
                             String password,
                             boolean fromSocial,
                             Collection<? extends GrantedAuthority> authorities,
                             Map<String, Object> attr
                             ) {
        this(username, password, fromSocial, authorities);
        this.attr = attr;
    }


    public ClubAuthMemberDTO(String username,
                             String password,
                             boolean fromSocial,
                             Collection<? extends GrantedAuthority> authorities
                             ) {
        super(username, password, authorities);
        this.email = username;
        this.fromSocial = fromSocial;
        this.password = password;
    }

    @Override
    public Map<String, Object> getAttributes(){
        return this.attr;
    }

}
