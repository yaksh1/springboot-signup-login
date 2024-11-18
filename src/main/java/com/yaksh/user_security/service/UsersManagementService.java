package com.yaksh.user_security.service;

import com.yaksh.user_security.Exception.*;
import com.yaksh.user_security.dto.ReqRes;
import com.yaksh.user_security.entity.ChangePassword;
import com.yaksh.user_security.entity.OurUsers;
import com.yaksh.user_security.entity.VerifyUser;
import com.yaksh.user_security.repository.PasswordTokenRepo;
import com.yaksh.user_security.repository.UsersRepo;
import com.yaksh.user_security.utils.JWTUtils;
import com.yaksh.user_security.utils.ValidationChecks;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UsersManagementService {

    private final ValidationChecks validationChecks;
    @Autowired
    private UsersRepo usersRepo;
    @Autowired
    private PasswordTokenRepo passwordTokenRepo;
    @Autowired
    private JWTUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EmailService emailService;




    public ReqRes register(ReqRes registrationRequest){
        ReqRes resp = new ReqRes();
        try {
//            if(!validationChecks.isValidEmail(registrationRequest.getEmail())){
//                throw new CustomValidationException(
//                        registrationRequest.getEmail()+" is an invalid email, you must be a registered student with MITWPU to enter the site."
//                        , ErrorCode.INVALID_EMAIL);
//            }
            if(validationChecks.isUserPresent(registrationRequest.getEmail())){
                throw new CustomValidationException("User already exists with email: " + registrationRequest.getEmail()
                        , ErrorCode.USER_ALREADY_EXISTS);
            }
            if(!validationChecks.isValidPassword(registrationRequest.getPassword())){
                throw new CustomValidationException(
                        "Password must be at least 8 characters long and contain an uppercase letter, lowercase letter, a digit, and a special character."
                        , ErrorCode.INVALID_PASSWORD);
            }
            OurUsers ourUser = new OurUsers();
            // generate verification token for user
            ourUser.setVerificationCode(generateVerificationCode());
            // set expiry of token to 15 minutes
            ourUser.setVerificationExpiresAt(LocalDateTime.now().plusMinutes(15));
            // account is not enabled yet
            ourUser.setEnabled(false);
            ourUser.setEmail(registrationRequest.getEmail());
            ourUser.setRole(registrationRequest.getRole());
            ourUser.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
            OurUsers ourUsersResult = usersRepo.save(ourUser);
            sendVerificationEmail(ourUser);
            if (ourUsersResult.getId()>0) {
                resp.setOurUsers((ourUsersResult));
                resp.setMessage("User Saved Successfully");
                resp.setStatusCode(200);
            }
        }
        catch (CustomValidationException e){
            throw e;
        }
        catch (Exception e){
            resp.setStatusCode(500);
            resp.setError(e.getMessage());
        }
        return resp;
    }

    public ReqRes verifyUser(VerifyUser verifyUser){
        ReqRes response = new ReqRes();
        Optional<OurUsers> optionalUser = usersRepo.findByEmail(verifyUser.getEmail());
        if(optionalUser.isPresent()){
            OurUsers user = optionalUser.get();
            if(validationChecks.isOtpExpired(user.getVerificationExpiresAt())){
                throw new CustomValidationException("Your code is expired, please request for a new code",ErrorCode.OTP_EXPIRED);
            }
            if(user.getVerificationCode().equals(verifyUser.getOtp())){
                user.setEnabled(true);
                user.setVerificationExpiresAt(null);
                user.setVerificationCode(null);
                usersRepo.save(user);
                response.setMessage("Account verified.");
                response.setStatusCode(200);

                return response;
            }else{
                throw new CustomValidationException("Invalid Verification Code,please try again.",ErrorCode.INVALID_OTP);
            }
        }else{
            throw new CustomValidationException("This account does not exists.",ErrorCode.USER_NOT_FOUND);
        }
    }

    public ReqRes resendVerification(String email){
        ReqRes resp = new ReqRes();
        Optional<OurUsers> optionalUser = usersRepo.findByEmail(email);
        if(optionalUser.isPresent()){
            OurUsers user = optionalUser.get();
            if(user.isEnabled()){
                throw new CustomValidationException("User is Already Verified",ErrorCode.USER_ALREADY_VERIFIED);
            }
            user.setVerificationCode(generateVerificationCode());
            user.setVerificationExpiresAt(LocalDateTime.now().plusMinutes(15));
            sendVerificationEmail(user);
            OurUsers OurUser = usersRepo.save(user);
            if(OurUser.getId()>0){
                resp.setOurUsers(OurUser);
                resp.setMessage("Email Verification code sent to email id: "+ email);
                resp.setStatusCode(200);
            }
            return resp;

        }else{
            throw new CustomValidationException("This account does not exists.",ErrorCode.USER_NOT_FOUND);
        }
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = random.nextInt(900000)+100000;
        return String.valueOf(code);
    }

    private void sendVerificationEmail(OurUsers user) {
        String subject = "Account verification code";
        String otp = user.getVerificationCode();
        String htmlMessage = "<html>"
                + "<body style=\"font-family: Arial, sans-serif;\">"
                + "<div style=\"background-color: #f5f5f5; padding: 20px;\">"
                + "<h2 style=\"color: #333;\">Welcome to our app!</h2>"
                + "<p style=\"font-size: 16px;\">Please enter the verification code below to continue:</p>"
                + "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">"
                + "<h3 style=\"color: #333;\">Verification Code:</h3>"
                + "<p style=\"font-size: 18px; font-weight: bold; color: #007bff;\">" + otp + "</p>"
                + "</div>"
                + "</div>"
                + "</body>"
                + "</html>";

        try {
            emailService.sendEmailVerification(user.getEmail(), subject, htmlMessage);
        } catch (MessagingException e) {
            // Handle email sending exception
            e.printStackTrace();
        }
    }

    public ReqRes login(ReqRes loginRequest){
        ReqRes response = new ReqRes();
        try {

            if(!validationChecks.isUserPresent(loginRequest.getEmail())){
                throw new CustomValidationException("User Not Found. Please check your email.",ErrorCode.USER_NOT_FOUND);
            }
            OurUsers users = usersRepo.findByEmail(loginRequest.getEmail()).orElse(null);
            if(!users.isEnabled()){
                throw new CustomValidationException("Account is not verified,please verify your account.",ErrorCode.ACCOUNT_NOT_VERIFIED);
            }
            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),
                            loginRequest.getPassword()));

            var user = usersRepo.findByEmail(loginRequest.getEmail()).orElseThrow();
            var jwt = jwtUtils.generateToken(user);
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRole(user.getRole());
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("24Hrs");
            response.setMessage("Successfully Logged In");

        }
        catch (CustomValidationException e){
            throw e;
        }
        catch (AuthenticationException e){
            throw e;
        }
        catch (Exception e){
            response.setStatusCode(500);
            response.setMessage(e.getMessage());
        }
        return response;
    }

    public ReqRes forgotPassword(String email) {
        ReqRes response = new ReqRes();

        try{

            if(validationChecks.isUserPresent(email)){
                String token = generatePasswordToken();
                ChangePassword body = new ChangePassword();
                body.setEmail(email);
                String encodedToken = DigestUtils.appendMd5DigestAsHex(token.getBytes(), new StringBuilder()).toString();
                body.setPasswordToken(encodedToken);
                body.setPasswordTokenExpiresAt(LocalDateTime.now().plusMinutes(15));
                passwordTokenRepo.save(body);
                String subject = "Password reset token";
                String htmlMessage = "<html>"
                        + "<body style=\"font-family: Arial, sans-serif;\">"
                        + "<div style=\"background-color: #f5f5f5; padding: 20px;\">"
                        + "<h2 style=\"color: #333;\">Welcome to our app!</h2>"
                        + "<p style=\"font-size: 16px;\">Please click on the link below to continue:</p>"
                        + "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">"
                        + "<h3 style=\"color: #333;\">Password Token:</h3>"
                        + "<p style=\"font-size: 18px; font-weight: bold; color: #007bff;\">" + "http://localhost:8080/auth/reset-password?token="+ token + "</p>"
                        + "</div>"
                        + "</div>"
                        + "</body>"
                        + "</html>";
                emailService.sendEmailVerification(email, subject, htmlMessage);

            }else{
                throw new CustomValidationException(
                        "Account does not exists.",
                        ErrorCode.USER_NOT_FOUND);
            }

            response.setStatusCode(200);
            response.setMessage("Password Token Successfully sent");
            return response;
        }catch (CustomValidationException e){
            throw e;
        }catch (MessagingException e) {
            response.setStatusCode(500);
            response.setMessage("error: "+e.getMessage());
            return response;
        }
        catch (Exception e){
            response.setStatusCode(500);
            response.setMessage("error: "+e.getMessage());
            return response;
        }
    }

    public static String generatePasswordToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[48]; // 48 bytes give ~64 Base64 characters
        secureRandom.nextBytes(randomBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        return token.substring(0, 64);
    }

    public ReqRes resetPassword(String token,String newPassword) {
        ReqRes response = new ReqRes();

        try {
            // Hash the token for lookup
            String encodedToken = DigestUtils.appendMd5DigestAsHex(token.getBytes(), new StringBuilder()).toString();

            // Retrieve the ChangePassword entity directly using the hashed token
            ChangePassword tokenEntity = passwordTokenRepo.findByPasswordToken(encodedToken);
            if (tokenEntity == null) {
                throw new CustomValidationException("Invalid password reset token.", ErrorCode.INVALID_TOKEN);
            }

            // Check token expiration
            if (tokenEntity.getPasswordTokenExpiresAt().isBefore(LocalDateTime.now())) {
                throw new CustomValidationException("Password reset token has expired.", ErrorCode.TOKEN_EXPIRED);
            }

            // Validate the new password against security rules
            if (!validationChecks.isValidPassword(newPassword)) {
                throw new CustomValidationException(
                        "Password must be at least 8 characters long and contain an uppercase letter, lowercase letter, a digit, and a special character.",
                        ErrorCode.INVALID_PASSWORD
                );
            }

            // Retrieve the user associated with the token
            OurUsers user = usersRepo.findByEmail(tokenEntity.getEmail())
                    .orElseThrow(() -> new CustomValidationException("User not found.", ErrorCode.USER_NOT_FOUND));

            // Ensure the user's account is active and verified
            if (!user.isEnabled()) {
                throw new CustomValidationException("Account is not verified. Please verify your account.", ErrorCode.ACCOUNT_NOT_VERIFIED);
            }

            // Update the user's password
            user.setPassword(passwordEncoder.encode(newPassword));
            usersRepo.save(user);

            // Clean up all password reset tokens for the user
            passwordTokenRepo.deleteByEmail(tokenEntity.getEmail());

            // Return success response
            response.setStatusCode(200);
            response.setMessage("Password successfully changed.");
            return response;
        } catch (CustomValidationException e) {
            throw e; // Re-throw custom exceptions to be handled by the exception handler
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("An error occurred: " + e.getMessage());
            return response;
        }
    }


    public ReqRes refreshToken(ReqRes refreshTokenReqiest){
        ReqRes response = new ReqRes();
        try{
            String ourEmail = jwtUtils.extractUsername(refreshTokenReqiest.getToken());
            OurUsers users = usersRepo.findByEmail(ourEmail).orElseThrow();
            if (jwtUtils.isTokenValid(refreshTokenReqiest.getToken(), users)) {
                var jwt = jwtUtils.generateToken(users);
                response.setStatusCode(200);
                response.setToken(jwt);
                response.setRefreshToken(refreshTokenReqiest.getToken());
                response.setExpirationTime("24Hr");
                response.setMessage("Successfully Refreshed Token");
            }
            response.setStatusCode(200);
            return response;

        }catch (Exception e){
            response.setStatusCode(500);
            response.setMessage(e.getMessage());
            return response;
        }
    }


    public ReqRes getAllUsers() {
        ReqRes reqRes = new ReqRes();

        try {
            List<OurUsers> result = usersRepo.findAll();
            if (!result.isEmpty()) {
                reqRes.setOurUsersList(result);
                reqRes.setStatusCode(200);
                reqRes.setMessage("Successful");
            } else {
                throw new CustomValidationException("Users not found",ErrorCode.DATA_NOT_FOUND);
            }
            return reqRes;
        }catch (CustomValidationException e){
            throw e;
        }
        catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred: " + e.getMessage());
            return reqRes;
        }
    }


    public ReqRes getUsersById(String email) {
        ReqRes reqRes = new ReqRes();
        try {
            OurUsers usersById = usersRepo.findByEmail(email).orElseThrow(() -> new CustomValidationException("User Not found",ErrorCode.USER_NOT_FOUND));
            reqRes.setOurUsers(usersById);
            reqRes.setStatusCode(200);
            reqRes.setMessage("Users with email id '" + email + "' found successfully");
        }catch (CustomValidationException e){
            throw e;
        }
        catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred: " + e.getMessage());
        }
        return reqRes;
    }


    public ReqRes deleteUser(String email) {
        ReqRes reqRes = new ReqRes();
        try {
            Optional<OurUsers> userOptional = usersRepo.findByEmail(email);
            if (userOptional.isPresent()) {
                usersRepo.deleteById(userOptional.get().getId());
                reqRes.setStatusCode(200);
                reqRes.setMessage("User deleted successfully");
            } else {
                throw new CustomValidationException("User not found.",ErrorCode.USER_NOT_FOUND);
            }
        }catch (CustomValidationException e){
            throw e;
        }
        catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred while deleting user: " + e.getMessage());
        }
        return reqRes;
    }

    public ReqRes updateUser(String email, OurUsers updatedUser) {
        ReqRes reqRes = new ReqRes();
        try {
            Optional<OurUsers> userOptional = usersRepo.findByEmail(email);
            if (userOptional.isPresent()) {
                OurUsers existingUser = userOptional.get();
                existingUser.setEmail(updatedUser.getEmail());
                existingUser.setRole(updatedUser.getRole());

                // Check if password is present in the request
                if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
                    // Encode the password and update it
                    existingUser.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
                }

                OurUsers savedUser = usersRepo.save(existingUser);
                reqRes.setOurUsers(savedUser);
                reqRes.setStatusCode(200);
                reqRes.setMessage("User updated successfully");
            } else {
                throw new CustomValidationException("User not found.",ErrorCode.USER_NOT_FOUND);
            }
        }catch (CustomValidationException e){
            throw e;
        }
        catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred while updating user: " + e.getMessage());
        }
        return reqRes;
    }


    public ReqRes getMyInfo(String email){
        ReqRes reqRes = new ReqRes();
        try {
            Optional<OurUsers> userOptional = usersRepo.findByEmail(email);
            if (userOptional.isPresent()) {
                reqRes.setOurUsers(userOptional.get());
                reqRes.setStatusCode(200);
                reqRes.setMessage("successful");
            } else {
                throw new CustomValidationException("User not found.",ErrorCode.USER_NOT_FOUND);
            }

        }catch (CustomValidationException e){
            throw e;
        }
        catch (Exception e){
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred while getting user info: " + e.getMessage());
        }
        return reqRes;

    }


}
