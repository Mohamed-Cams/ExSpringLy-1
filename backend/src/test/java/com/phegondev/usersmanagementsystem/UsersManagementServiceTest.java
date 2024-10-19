package com.phegondev.usersmanagementsystem.service;

import com.phegondev.usersmanagementsystem.dto.ReqRes;
import com.phegondev.usersmanagementsystem.entity.OurUsers;
import com.phegondev.usersmanagementsystem.repository.UsersRepo;
import com.phegondev.usersmanagementsystem.service.UsersManagementService;
import com.phegondev.usersmanagementsystem.utils.JWTUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class UsersManagementServiceTest {

    @Mock
    private UsersRepo usersRepo;

    @Mock
    private JWTUtils jwtUtils;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UsersManagementService usersManagementService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void registerSuccessTest() {
        // Arrange
        ReqRes registrationRequest = new ReqRes();
        registrationRequest.setEmail("test@example.com");
        registrationRequest.setCity("Test City");
        registrationRequest.setRole("USER");
        registrationRequest.setName("Test User");
        registrationRequest.setPassword("password");

        OurUsers savedUser = new OurUsers();
        savedUser.setId(1);
        savedUser.setEmail("test@example.com");

        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(usersRepo.save(any(OurUsers.class))).thenReturn(savedUser);

        // Act
        ReqRes response = usersManagementService.register(registrationRequest);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertNotNull(response.getOurUsers());
        verify(usersRepo, times(1)).save(any(OurUsers.class));
    }

    @Test
    void registerFailureTest() {
        // Arrange
        ReqRes registrationRequest = new ReqRes();
        registrationRequest.setEmail("test@example.com");

        when(usersRepo.save(any(OurUsers.class))).thenThrow(new RuntimeException("Error"));

        // Act
        ReqRes response = usersManagementService.register(registrationRequest);

        // Assert
        assertEquals(500, response.getStatusCode());
        assertNotNull(response.getError());
        verify(usersRepo, times(1)).save(any(OurUsers.class));
    }

    @Test
    void loginSuccessTest() {
        // Arrange
        ReqRes loginRequest = new ReqRes();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password");

        OurUsers user = new OurUsers();
        user.setEmail("test@example.com");
        user.setRole("USER");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(null); // No exception means authentication succeeded
        when(usersRepo.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(jwtUtils.generateToken(any(OurUsers.class))).thenReturn("token");
        when(jwtUtils.generateRefreshToken(any(HashMap.class), any(OurUsers.class)))
                .thenReturn("refreshToken");

        // Act
        ReqRes response = usersManagementService.login(loginRequest);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertEquals("token", response.getToken());
        assertEquals("USER", response.getRole());
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void loginFailureTest() {
        // Arrange
        ReqRes loginRequest = new ReqRes();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("wrongPassword");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new RuntimeException("Authentication failed"));

        // Act
        ReqRes response = usersManagementService.login(loginRequest);

        // Assert
        assertEquals(500, response.getStatusCode());
        assertEquals("Authentication failed", response.getMessage());
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void getAllUsersTest() {
        // Arrange
        OurUsers user1 = new OurUsers();
        user1.setId(1);
        user1.setEmail("user1@example.com");

        OurUsers user2 = new OurUsers();
        user2.setId(2);
        user2.setEmail("user2@example.com");

        when(usersRepo.findAll()).thenReturn(List.of(user1, user2));

        // Act
        ReqRes response = usersManagementService.getAllUsers();

        // Assert
        assertEquals(200, response.getStatusCode());
        assertEquals(2, response.getOurUsersList().size());
        verify(usersRepo, times(1)).findAll();
    }

    @Test
    void getUsersByIdTest() {
        // Arrange
        OurUsers user = new OurUsers();
        user.setId(1);
        user.setEmail("user@example.com");

        when(usersRepo.findById(anyInt())).thenReturn(Optional.of(user));

        // Act
        ReqRes response = usersManagementService.getUsersById(1);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertNotNull(response.getOurUsers());
        assertEquals("user@example.com", response.getOurUsers().getEmail());
        verify(usersRepo, times(1)).findById(anyInt());
    }

    @Test
    void refreshTokenSuccessTest() {
        // Arrange
        ReqRes refreshTokenRequest = new ReqRes();
        refreshTokenRequest.setToken("validRefreshToken");

        OurUsers user = new OurUsers();
        user.setEmail("test@example.com");

        when(jwtUtils.extractUsername(anyString())).thenReturn("test@example.com");
        when(usersRepo.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(jwtUtils.isTokenValid(anyString(), any(OurUsers.class))).thenReturn(true);
        when(jwtUtils.generateToken(any(OurUsers.class))).thenReturn("newJwtToken");

        // Act
        ReqRes response = usersManagementService.refreshToken(refreshTokenRequest);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertEquals("newJwtToken", response.getToken());
        assertEquals("validRefreshToken", response.getRefreshToken());
        verify(jwtUtils, times(1)).generateToken(any(OurUsers.class));
    }

    @Test
    void refreshTokenInvalidTest() {
        // Arrange
        ReqRes refreshTokenRequest = new ReqRes();
        refreshTokenRequest.setToken("invalidToken");

        when(jwtUtils.extractUsername(anyString())).thenReturn("test@example.com");
        when(usersRepo.findByEmail(anyString())).thenReturn(Optional.of(new OurUsers()));
        when(jwtUtils.isTokenValid(anyString(), any(OurUsers.class))).thenReturn(false);

        // Act
        ReqRes response = usersManagementService.refreshToken(refreshTokenRequest);

        // Assert
        assertEquals(500, response.getStatusCode());
        assertNull(response.getToken());
        verify(jwtUtils, times(1)).isTokenValid(anyString(), any(OurUsers.class));
    }

    @Test
    void deleteUserSuccessTest() {
        // Arrange
        OurUsers user = new OurUsers();
        user.setId(1);
        user.setEmail("test@example.com");

        when(usersRepo.findById(anyInt())).thenReturn(Optional.of(user));

        // Act
        ReqRes response = usersManagementService.deleteUser(1);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertEquals("User deleted successfully", response.getMessage());
        verify(usersRepo, times(1)).deleteById(anyInt());
    }

    @Test
    void deleteUserNotFoundTest() {
        // Arrange
        when(usersRepo.findById(anyInt())).thenReturn(Optional.empty());

        // Act
        ReqRes response = usersManagementService.deleteUser(1);

        // Assert
        assertEquals(404, response.getStatusCode());
        assertEquals("User not found for deletion", response.getMessage());
        verify(usersRepo, times(0)).deleteById(anyInt());
    }

    @Test
    void updateUserSuccessTest() {
        // Arrange
        OurUsers existingUser = new OurUsers();
        existingUser.setId(1);
        existingUser.setEmail("test@example.com");
        existingUser.setName("Old Name");

        OurUsers updatedUser = new OurUsers();
        updatedUser.setEmail("newemail@example.com");
        updatedUser.setName("New Name");
        updatedUser.setCity("New City");

        when(usersRepo.findById(anyInt())).thenReturn(Optional.of(existingUser));
        when(usersRepo.save(any(OurUsers.class))).thenReturn(updatedUser);

        // Act
        ReqRes response = usersManagementService.updateUser(1, updatedUser);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertNotNull(response.getOurUsers());
        assertEquals("newemail@example.com", response.getOurUsers().getEmail());
        assertEquals("New Name", response.getOurUsers().getName());
        verify(usersRepo, times(1)).findById(anyInt());
        verify(usersRepo, times(1)).save(any(OurUsers.class));
    }

    @Test
    void updateUserNotFoundTest() {
        // Arrange
        OurUsers updatedUser = new OurUsers();
        updatedUser.setEmail("newemail@example.com");

        when(usersRepo.findById(anyInt())).thenReturn(Optional.empty());

        // Act
        ReqRes response = usersManagementService.updateUser(1, updatedUser);

        // Assert
        assertEquals(404, response.getStatusCode());
        assertEquals("User not found for update", response.getMessage());
        verify(usersRepo, times(1)).findById(anyInt());
        verify(usersRepo, times(0)).save(any(OurUsers.class));
    }

    @Test
    void getMyInfoSuccessTest() {
        // Arrange
        OurUsers user = new OurUsers();
        user.setEmail("test@example.com");

        when(usersRepo.findByEmail(anyString())).thenReturn(Optional.of(user));

        // Act
        ReqRes response = usersManagementService.getMyInfo("test@example.com");

        // Assert
        assertEquals(200, response.getStatusCode());
        assertNotNull(response.getOurUsers());
        assertEquals("test@example.com", response.getOurUsers().getEmail());
        verify(usersRepo, times(1)).findByEmail(anyString());
    }

    @Test
    void getMyInfoUserNotFoundTest() {
        // Arrange
        when(usersRepo.findByEmail(anyString())).thenReturn(Optional.empty());

        // Act
        ReqRes response = usersManagementService.getMyInfo("test@example.com");

        // Assert
        assertEquals(404, response.getStatusCode());
        assertEquals("User not found for update", response.getMessage());
        verify(usersRepo, times(1)).findByEmail(anyString());
    }

}
