package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {
	@GetMapping("/login")
	public String login(@RequestParam(value="error", required = false) String error, @RequestParam(value="exception", required = false) String exception, Model model){
		model.addAttribute("error", error);
		model.addAttribute("exception", exception);

		return "user/login/login";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response){
		// 로그인을 한 인증객체
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if(authentication != null) {
			// 로그아웃 처리를 하는 핸들러 - HttpServletRequest, HttpServletResponse, Authentication 필요
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}

		return "redirect:/login";
	}

	@GetMapping("/denied")
	public String accessDenied(@RequestParam(value="exception", required = false) String exception, Model model) {
		Account account = (Account)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		model.addAttribute("username", account.getUsername());
		model.addAttribute("exception", exception);

		return "user/login/denied";
	}
}
