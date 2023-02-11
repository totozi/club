package org.zerock.club.security.filter;

import lombok.extern.log4j.Log4j2;
import net.minidev.json.JSONObject;
import org.springframework.security.core.parameters.P;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.club.security.util.JWTUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Log4j2       // 추상 클래스로 제공되는 필터, 매번 동작하는 기본 필터, SecurityConfig에서 bean으로 등록
public class ApiCheckFilter extends OncePerRequestFilter {

    private AntPathMatcher antPathMatcher;
    private String pattern;
    private JWTUtil jwtUtil;

    public ApiCheckFilter(String pattern, JWTUtil jwtUtil) {
        this.antPathMatcher = new AntPathMatcher();
        this.pattern = pattern;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        log.info("REQUESTURI : " + request.getRequestURL());
        log.info(antPathMatcher.match(pattern, request.getRequestURI()));

        if(antPathMatcher.match(pattern, request.getRequestURI())) {

            log.info("ApiCheckFilter....................................");
            log.info("ApiCheckFilter....................................");
            log.info("ApiCheckFilter....................................");

            boolean checkHeader = checkAuthHeader(request);

            if(checkHeader) {
                filterChain.doFilter(request, response);
                return;
            } else {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                // json 리턴 및 한글 깨짐 수정
                response.setContentType("application/json;charset=utf-8");
                JSONObject json = new JSONObject();
                String message = "FAIL CHECK API TOKEN";
                json.put("code", "403");
                json.put("message", message);

                PrintWriter out = response.getWriter();
                out.print(json);

                return;
            }
        }
        filterChain.doFilter(request, response); // 다음 단계의 필터로 넘어가는 역할

    }
    // 헤더에서 Authorization 추출 후 인증
    // 쿠키나 세션을 이용할 수 없는 서버나 어플리케이션의 경우 이런 방법을 사용
    private boolean checkAuthHeader(HttpServletRequest request) {
        boolean checkResult = false;

        String authHeader = request.getHeader("Authorization");

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            log.info("Authorization exists : " + authHeader);

            try {
                String email = jwtUtil.validateAndExtract(authHeader.substring(7));
                log.info("validate result : " + email);
                checkResult = email.length() > 0;

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return checkResult;
    }


}
