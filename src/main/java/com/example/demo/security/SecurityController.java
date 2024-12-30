package com.example.demo.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @PreAuthorize("hasRole('BASICUSER') or hasRole('ADMIN')")
    @GetMapping("/basic")
    public String basic(){
        return "BASIC";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/special")
    public String special(){
        return "SPECIAL";
    }
}
