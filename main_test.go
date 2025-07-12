package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestMain sets up the test environment and runs the tests.
func TestMain(m *testing.M) {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file:", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()
	os.Exit(code)
}

// setupTestApp initializes a test App instance with an in-memory SQLite database.
func setupTestApp(t *testing.T) *App {
	config := &Config{
		DatabaseURL:       "sqlite::memory:", // In-memory database for testing
		JWTSecret:         "testsecret",      // Use a test-specific secret
		Port:              "8080",
		CORSAllowedOrigin: "http://localhost:3000",
		DBSchema:          "public",
	}

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	// Migrate the database
	if err := db.AutoMigrate(&User{}); err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	app := &App{
		DB:     db,
		Router: mux.NewRouter(),
		Config: config,
		Logger: logger,
	}

	app.setupRoutes()
	return app
}

// TestSignup tests the /signup endpoint.
func TestSignup(t *testing.T) {
	app := setupTestApp(t)

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Successful Signup (Admin)",
			payload:        `{"name":"Admin User","email":"admin@example.com","password":"admin123","role":"admin"}`,
			expectedStatus: http.StatusCreated,
			expectedBody:   `"email":"admin@example.com"`,
		},
		{
			name:           "Successful Signup (User)",
			payload:        `{"name":"Regular User","email":"user@example.com","password":"user123","role":"user"}`,
			expectedStatus: http.StatusCreated,
			expectedBody:   `"email":"user@example.com"`,
		},
		{
			name:           "Duplicate Email",
			payload:        `{"name":"Another Admin","email":"admin@example.com","password":"admin123","role":"admin"}`,
			expectedStatus: http.StatusConflict,
			expectedBody:   `{"message":"Email already in use"}`,
		},
		{
			name:           "Invalid Input (Missing Email)",
			payload:        `{"name":"No Email","password":"test123","role":"user"}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"message":"Email and password are required"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean the database
			app.DB.Exec("DELETE FROM users")

			req, err := http.NewRequest("POST", "/signup", bytes.NewBufferString(tt.payload))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			app.Router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, "Unexpected status code")
			assert.Contains(t, rr.Body.String(), tt.expectedBody, "Unexpected response body")
		})
	}
}

// TestSignin tests the /signin endpoint.
func TestSignin(t *testing.T) {
	app := setupTestApp(t)

	// Create test users
	users := []User{
		{
			Name:     "Admin User",
			Email:    "admin@example.com",
			Password: hashPassword(t, "admin123"),
			Role:     "admin",
		},
		{
			Name:     "Regular User",
			Email:    "user@example.com",
			Password: hashPassword(t, "user123"),
			Role:     "user",
		},
	}
	for _, user := range users {
		if err := app.DB.Create(&user).Error; err != nil {
			t.Fatalf("Failed to create test user: %v", err)
		}
	}

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid Admin Credentials",
			payload:        `{"email":"admin@example.com","password":"admin123"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   `"role":"admin"`,
		},
		{
			name:           "Valid User Credentials",
			payload:        `{"email":"user@example.com","password":"user123"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   `"role":"user"`,
		},
		{
			name:           "Invalid Password",
			payload:        `{"email":"admin@example.com","password":"wrongpassword"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"message":"Invalid email or password"}`,
		},
		{
			name:           "Non-existent User",
			payload:        `{"email":"nonexistent@example.com","password":"test123"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"message":"Invalid email or password"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/signin", bytes.NewBufferString(tt.payload))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			app.Router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, "Unexpected status code")
			assert.Contains(t, rr.Body.String(), tt.expectedBody, "Unexpected response body")

			// Verify token structure for successful sign-in
			if tt.expectedStatus == http.StatusOK {
				var resp TokenResponse
				err = json.Unmarshal(rr.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.Token, "JWT token should not be empty")
				assert.NotEmpty(t, resp.RefreshToken, "Refresh token should not be empty")
			}
		})
	}
}

// TestProtectedEndpoints tests the /admin and /user endpoints.
func TestProtectedEndpoints(t *testing.T) {
	app := setupTestApp(t)

	// Create test users
	users := []User{
		{
			Name:     "Admin User",
			Email:    "admin@example.com",
			Password: hashPassword(t, "admin123"),
			Role:     "admin",
		},
		{
			Name:     "Regular User",
			Email:    "user@example.com",
			Password: hashPassword(t, "user123"),
			Role:     "user",
		},
	}
	for _, user := range users {
		if err := app.DB.Create(&user).Error; err != nil {
			t.Fatalf("Failed to create test user: %v", err)
		}
	}

	// Generate JWTs
	adminToken, _ := app.generateJWT("admin@example.com", "admin")
	userToken, _ := app.generateJWT("user@example.com", "user")

	tests := []struct {
		name           string
		endpoint       string
		token          string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Admin Access /admin (Valid Token)",
			endpoint:       "/admin",
			token:          adminToken,
			expectedStatus: http.StatusOK,
			expectedBody:   "Welcome, Admin",
		},
		{
			name:           "User Access /admin (Wrong Role)",
			endpoint:       "/admin",
			token:          userToken,
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"message":"Insufficient role permissions"}`,
		},
		{
			name:           "User Access /user (Valid Token)",
			endpoint:       "/user",
			token:          userToken,
			expectedStatus: http.StatusOK,
			expectedBody:   "Welcome, User",
		},
		{
			name:           "Admin Access /user (Wrong Role)",
			endpoint:       "/user",
			token:          adminToken,
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"message":"Insufficient role permissions"}`,
		},
		{
			name:           "Missing Token (/admin)",
			endpoint:       "/admin",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"message":"Missing or invalid Authorization header"}`,
		},
		{
			name:           "Invalid Token (/admin)",
			endpoint:       "/admin",
			token:          "invalid_token",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"message":"Invalid or expired token"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.endpoint, nil)
			assert.NoError(t, err)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			rr := httptest.NewRecorder()
			app.Router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, "Unexpected status code")
			assert.Contains(t, rr.Body.String(), tt.expectedBody, "Unexpected response body")
		})
	}
}

// TestIndex tests the public / endpoint.
func TestIndex(t *testing.T) {
	app := setupTestApp(t)

	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	app.Router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "Unexpected status code")
	assert.Equal(t, "HOME PUBLIC INDEX PAGE", rr.Body.String(), "Unexpected response body")
}

// hashPassword generates a hashed password for test users.
func hashPassword(t *testing.T, password string) string {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	return string(hashed)
}
