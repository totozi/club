package org.zerock.club.security.handler;


import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.zerock.club.security.dto.ClubAuthMemberDTO;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Log4j2
public class ClubLoginSuccessHandler implements AuthenticationSuccessHandler {
    // 로그인 성공 이후 처리를 담당하는 용도로 AuthenticationSuccessHandler를 구현

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private PasswordEncoder passwordEncoder;

    public ClubLoginSuccessHandler(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        log.info("-------------------------------------");
        log.info("onAuthenticationSuccess");

        ClubAuthMemberDTO authMemberDTO = (ClubAuthMemberDTO) authentication.getPrincipal();

        boolean fromSocial = authMemberDTO.isFromSocial();

        log.info("Need Modify Member ? " + fromSocial);

        boolean passwordResult = passwordEncoder.matches("1111", authMemberDTO.getPassword());

        if(fromSocial && passwordResult) {
            redirectStrategy.sendRedirect(request, response, "/sample/admin?from=social");
            // 소셜 로그인한 사용자가 이후의 행동을 할 수 있도록 redirect (임시 지정한 비밀번호의 변경이나 닉네임 설정 등...)
        }
        // 이 설정이 없으면 api 설정 시 정한 redirect url로 가는듯?


    }


}
