package com.yaksh.user_security.entity;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;

@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetTokenId implements Serializable {
    private String email;
    private String passwordToken;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PasswordResetTokenId that = (PasswordResetTokenId) o;
        return Objects.equals(email, that.email) && Objects.equals(passwordToken, that.passwordToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(email, passwordToken);
    }
}
