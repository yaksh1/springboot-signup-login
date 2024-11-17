package com.yaksh.user_security.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifyUser {
    private String email;
    private String otp;
}
