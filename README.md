# Springboot Authentication

This project is a quickstart template of registration and login process with JWT authentication and email verification.

## Overview

- **Backend (Spring Boot)**: Provides secure endpoints for user authentication (login/signup), email verification (OTP), password management, review submission, and data storage.
  - **JWT Authentication**: Secures endpoints with JWT tokens, ensuring only authorized users can access restricted features.
  - **Bcrypt**: Passwords are hashed using Bcrypt before storing them in the database.
  - **Database**: User data is stored in MySQL.

### Prerequisites

- **Java 11+** (for the backend)
- **MySQL** (for user data)
- **JWT** (for authentication)

## Features

- **User Authentication**: Login/signup with email verification using OTP.
- **JWT Token**: Used for securing API endpoints, ensuring only authorized users can access them.
- **Email Verification**: Sends OTP for user verification. Resend verification code available.
- **Change Password**: Users can change their passwords by clicking on link sent in mail.
- **Custom Exception Handling**: Handles common errors gracefully and provides meaningful feedback.
- **Database**:
  - **MySQL** for user data storage.
- **Bcrypt**: Passwords are securely hashed before storing in the database.

## Applications

**Important**: All API endpoints can be accessed here after running the backend - http://localhost:8080/swagger-ui/index.html#/. Make sure to put `/v3/api-docs` in explore search bar.

base url -> `http://localhost:8080`
- `/auth/register` - Register a new user
- `/auth/login` - Get a JWT token after successful login
- `/auth/verify` - Email verification with OTP
- `/auth/forgotPassword` - Get the password reset link in the registered mail
- `/auth/reset-password` - Reset the password for the registered mail
- `/auth/resend` - Resend email verification code


### Setup

1. **Setup MySQL Database**
- Create a MySQL database locally with your choice of name. For example I have created `login_signup`.


2. **Code Setup**

Clone the repository

```bash
git clone https://github.com/yaksh1/springboot-signup-login.git
```

Navigate to newly cretaed Folder

```bash
cd springboot-signup-login
```



  - Create a .env file
    - Fill the details of the project in the `sample-env.md` and paste it in your `.env` file.
    - For email app password watch this [video](https://www.youtube.com/watch?v=lSURGX0JHbA).
    - For JWT secret key use any from google or other source


  - Run the Springboot Application
    
```bash
./mvnw spring-boot:run
```

Backend runs on http://localhost:8080

### Mail Configuration

Make sure to specify valid `spring.mail.username` and `spring.mail.password` in the `application.properties` file to enable email services for sending verification emails. Without proper mail credentials, email functionality will not work.

