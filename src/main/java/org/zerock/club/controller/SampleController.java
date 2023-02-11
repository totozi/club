package org.zerock.club.controller;


import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.zerock.club.security.dto.ClubAuthMemberDTO;

@Controller
@Log4j2
@RequestMapping("/sample/")
public class SampleController {

    @GetMapping("/all")
    public void exAll(){
        log.info("exAll..........");
    }

//    @GetMapping("/member")
//    public void exMember(){
//        log.info("exMember..........");
//    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public void exAdmin(){
        log.info("exAdmin..........");
    }

    @GetMapping("/member")
    public void exMember(){

        log.info("exMember..........");

    }

    @PreAuthorize("#clubAuthMemberDTO != null && #clubAuthMemberDTO.username eq \"skgydnjs@gmail.com\"")
    @GetMapping("exOnly")
    public void exMemberOnly(@AuthenticationPrincipal ClubAuthMemberDTO clubAuthMemberDTO)
    {
        log.info("exOnly..........");
        log.info(clubAuthMemberDTO);

    }

}
