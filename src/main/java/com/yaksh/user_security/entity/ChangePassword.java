package com.yaksh.user_security.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.context.annotation.Primary;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@IdClass(PasswordResetTokenId.class)
@Table(name = "password_reset_tokens")
public class ChangePassword {
    @Id
    private String email;
    @Id
    private String passwordToken;
    private LocalDateTime passwordTokenExpiresAt;
}
