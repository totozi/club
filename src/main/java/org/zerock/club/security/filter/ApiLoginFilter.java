package org.zerock.club.security.filter;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.club.security.dto.ClubAuthMemberDTO;
import org.zerock.club.security.util.JWTUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Log4j2
public class ApiLoginFilter extends AbstractAuthenticationProcessingFilter {

    private JWTUtil jwtUtil;

    public ApiLoginFilter(String defaultFilterProcessesUrl, JWTUtil jwtUtil) {
        super(defaultFilterProcessesUrl);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
        throws AuthenticationException, IOException , ServletException {

        log.info("--------------------- ApiLoginFilter ------------------------");
        log.info("attemptAuthentication");

        String email = request.getParameter("email");
        String pw = request.getParameter("pw");

//        System.out.println(email);
//        System.out.println(pw);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(email, pw);

        System.out.println("authToken : " + authToken);

//        if(email == null) {
//            throw new BadCredentialsException("email cannot be null");
//        }

        return getAuthenticationManager().authenticate(authToken);
    }

    // 사용자에게 전송할 토큰 발행
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
        throws IOException, ServletException {

        log.info("--------------------ApiLoginFilter----------------------");
        log.info("successfulAuthentication : " + authResult);

        log.info(authResult.getPrincipal());

        // email address
        String email = ((ClubAuthMemberDTO)authResult.getPrincipal()).getUsername();

        String token = null;

        try{
            token = jwtUtil.generateToken(email); // 토큰 발행

            response.setContentType("text/plain");
            response.getOutputStream().write(token.getBytes()); // 사용자전송

        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
