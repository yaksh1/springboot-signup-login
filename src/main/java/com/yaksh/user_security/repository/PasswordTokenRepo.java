package com.yaksh.user_security.repository;

import com.yaksh.user_security.entity.ChangePassword;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface PasswordTokenRepo extends JpaRepository<ChangePassword,String> {
    ChangePassword findByPasswordToken(String token);
    // This method will delete all rows associated with the given email
    @Modifying
    @Transactional
    @Query("DELETE FROM ChangePassword cp WHERE cp.email = :email")
    void deleteByEmail(@Param("email") String email);


}
