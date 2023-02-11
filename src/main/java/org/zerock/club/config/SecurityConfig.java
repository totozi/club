package org.zerock.club.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.club.security.filter.ApiCheckFilter;
import org.zerock.club.security.filter.ApiLoginFilter;
import org.zerock.club.security.handler.ApiLoginFailHandler;
import org.zerock.club.security.handler.ClubLoginSuccessHandler;
import org.zerock.club.security.service.ClubUserDetailsService;
import org.zerock.club.security.util.JWTUtil;

/*
   시큐리티 관련 모든 설정이 추가되는 클래스
 */
@Configuration
@Log4j2
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
// SecurityConfig를 사용해서 지정된 URL에만 접근 제한을 거는 방식이 번거로우므로
// @EnableGlobalMethodSecurity 을 추가하고 접근 제한이 필요한 컨트롤러의 메서드에 @PreAuthoriz를 적용하는 게 더 편하다.
public class SecurityConfig {

    @Bean
    public JWTUtil jwtUtil(){
        return new JWTUtil();
    }

    @Autowired
    private ClubUserDetailsService clubUserDetailsService;
    /*
        BCryptPasswordEncoder : bcrypt 해시 함수를 이용해서 패스워드를 암호화하는 클래스
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    // 임시 사용자 지정
//    @Bean
//    public InMemoryUserDetailsManager userDetailsServie(){
//        UserDetails user = User.builder() // User 객체 생성
//                .username("user1")
//                .password(passwordEncoder().encode("1111")) // 패스워드 인코더 가져와서 1111 암호화
//                .roles("USER")
//                .build();
//
//        log.info("userDetailService..............");
//        log.info(user);
//
//        return new InMemoryUserDetailsManager(user);
//        // 메모리상에 있는 데이터를 이용하는 인증매니저(AuthenticationManager 생성)
//
//    }

    // SecurityFilterChain를 반환하는 메서드를 구성해서 접근 제한을 처리할 수 있다.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(clubUserDetailsService).passwordEncoder(passwordEncoder());

        // Get AuthenticationManager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        // 반드시 필요
        http.authenticationManager(authenticationManager);

//        http.authorizeHttpRequests((auth) -> {
//            auth.antMatchers("/sample/all").permitAll();
//            auth.antMatchers("/sample/member").hasRole("USER");
//
//            // antMathcers()는 앤트 스타일의 패턴으로 자원 선택
//            // permitAll()은 모든 사용자에게 허락 -> 로그인 안해도 가능
//        });
        // @EnableGlobalMethodSecurity 을 추가하고 접근 제한이 필요한 컨트롤러의 메서드에 @PreAuthoriz를 적용할 것이므로 주석 처리

        http.formLogin();
        //http.formLogin(formLogin -> formLogin.loginPage("/sample/login")); // 로그인화면은 이렇게 따로 지정 가능..
        http.csrf().disable(); // form 태그 사용시에는 보안상으로 권장
        // but 그게 아니면 발행하지 않는 경우도 있음..
        http.logout();

        http.oauth2Login().successHandler(successHandler()); // 로그인 성공 이후 처리를 담당하는 핸들러 설정

        // HttpSession을 이용하기 때문에 invalidatedHttpSession()과 deleteCookies() 등을 통해
        // 쿠키나 세션을 무효화 시킬 수 있도록 설정할 수 있다.

        http.rememberMe()
                .tokenValiditySeconds(60*60) // 쿠키를 얼마나 유지할 것인가.. 1시간
                .userDetailsService(clubUserDetailsService);
        // 소셜로그인은 쿠키가 생기지 않는다...
        http.addFilterBefore(apiCheckFilter(), UsernamePasswordAuthenticationFilter.class);

        http.addFilterBefore(apiLoginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /*
        1. 스프링에서는 User라는 용어를 회원이나 계정에 대해서 사용한다. 그래서 User라는 단어를 피하는 게 좋다.
        2. username은 이름이 아니라 id인 식별자이다.
        3. 스프링 시큐리티는 UserDetailsService를 통해 회원의 존재만을 먼저 가져오고 이후에 password 검증을 통하여
        Bad Cridential 결과를 만들어 낸다(인증)
        4. 인증 과정이 끝나면 원하는 URL(자원)에 접근할 수 있는 권한이 있는 지 확인(인가) -> Access Denied 같은 결과 생성

        - UserDetailsService는 loadUserByUsername()이라는 단 하나의 메서드만 가지고 있다.
        - UserDetails를 구현한 User 클래스가 있으므로 사용하면 편하다.
     */


    // 로그인 성공 이후 처리를 담당하는 Handler 설정
    @Bean
    public ClubLoginSuccessHandler successHandler(){
        return new ClubLoginSuccessHandler(passwordEncoder());
    }

    @Bean
    public ApiCheckFilter apiCheckFilter() {

        return new ApiCheckFilter("/notes/**/*", jwtUtil());
    }

    public ApiLoginFilter apiLoginFilter(AuthenticationManager authenticationManager){
        //        return new ApiCheckFilter("/notes/**/*"); // 특정 URL만을 위한 필터 설정

        ApiLoginFilter apiLoginFilter = new ApiLoginFilter("/api/login", jwtUtil());
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        apiLoginFilter.setAuthenticationFailureHandler(new ApiLoginFailHandler());

        return apiLoginFilter;
    }







}
