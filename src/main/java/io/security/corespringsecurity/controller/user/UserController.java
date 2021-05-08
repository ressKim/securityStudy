package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    //	@Autowired
//	private RoleRepository roleRepository;

    @GetMapping(value = "/users")
    public String createUser() throws Exception {
        return "user/login/register";
    }

    @PostMapping(value = "/users")
    public String createUser(AccountDto accountDto) throws Exception {

        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(accountDto.getPassword()));

        userService.createUser(account);

        return "redirect:/";
    }

    @GetMapping(value = "/myPage")
//	public String myPage(@AuthenticationPrincipal Account account, Authentication authentication, Principal principal) throws Exception {
    public String myPage() throws Exception {
        return "user/myPage";
    }

    //
    @GetMapping("/order")
    public String order() {
//		userService.order();
        return "user/myPage";
    }

}
