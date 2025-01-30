package com.saml.auth.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@CrossOrigin("*")
public class AuthController {  // Fixed typo in class name

    @GetMapping("/test")
    public ResponseEntity<String> test(@RequestParam(required = false) String param) {
        return ResponseEntity.ok("Test route is working! Param: " + param);
    }

    
}
