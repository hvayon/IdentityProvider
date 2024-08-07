package ru.hvayon.IdentityProvider.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import ru.hvayon.IdentityProvider.entities.Role;
import ru.hvayon.IdentityProvider.entities.User;
import ru.hvayon.IdentityProvider.repositories.RoleRepository;
import ru.hvayon.IdentityProvider.repositories.UserRepository;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

@RestController
@RequiredArgsConstructor
@RequestMapping("api")
public class MainController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/v1/callback")
    public String unsecuredData() {
        return "Unsecured data";
    }

    @GetMapping("/secured")
    public String securedData() {
        return "Secured data";
    }

    @GetMapping("/v1/admin")
    public String adminData() {
        return "Admin data";
    }

    @PostMapping("/v1/create/user")
    public void createUser(@RequestBody User user) {
        System.out.println("A new user has been created: " + user.getEmail());
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Role 'USER' not found"));

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        String encodedPassword = passwordEncoder.encode(user.getPassword());
        System.out.println(encodedPassword);
        user.setPassword(encodedPassword);

        userRepository.save(user);
    }

    @GetMapping("/v1/info")
    public String userData(Principal principal) {
        return principal.getName();
    }
}