package ru.hvayon.IdentityProvider.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.hvayon.IdentityProvider.dtos.JwtRequest;
import ru.hvayon.IdentityProvider.dtos.RegistrationUserDto;
import ru.hvayon.IdentityProvider.service.AuthService;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/")
public class AuthController {
    private final AuthService authService;

    @PostMapping("v1/authorize")
    public ResponseEntity<?> createAuthToken(@RequestBody JwtRequest authRequest) {
        return authService.createAuthToken(authRequest);
    }

    @PostMapping("v1/registration")
    public ResponseEntity<?> createNewUser(@RequestBody RegistrationUserDto registrationUserDto) {
        return authService.createNewUser(registrationUserDto);
    }
}