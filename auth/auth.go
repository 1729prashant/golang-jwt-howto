package auth

// The auth package provides functionality for JWT-based authentication in the application.
// It handles the creation of JWT tokens and refresh tokens, verifies JWTs for protected endpoints,
// and defines data structures for authentication requests and responses. The package uses the
// github.com/golang-jwt/jwt library to create and parse JWTs with the HS256 signing method.
// In a JWT system, this package is responsible for generating secure tokens during signin,
// validating tokens for protected routes, and enforcing role-based access control (e.g., restricting
// /admin to "admin" roles). It integrates with the config package for the JWT secret and the db package
// for user authentication. For production, it ensures secure token generation, robust validation,
// and standardized error responses to maintain security and usability.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang-jwt-howto/config"

	"github.com/golang-jwt/jwt"
)

// AuthRequest Struct
// Syntax: type AuthRequest struct { Email string; Password string }
// Description:
// The AuthRequest struct represents the JSON payload sent to the /signin endpoint to authenticate a user.
// It contains the user's email and password, which are used to verify credentials against the database.
// In a JWT system, this struct is used to parse the request body during signin, allowing the application
// to authenticate the user and generate a JWT token if credentials are valid. The struct uses JSON tags
// to map fields to JSON keys, ensuring proper deserialization of client requests.
// Fields:
// - Email (string): The user's email address, used to look up the user in the database.
// - Password (string): The plaintext password provided by the user, to be verified against the stored hashed password.
// JSON Tags:
// - json:"email": Maps the Email field to the "email" key in the JSON payload.
// - json:"password": Maps the Password field to the "password" key in the JSON payload.
// Usage in Production:
// - Use AuthRequest to deserialize JSON payloads in the /signin endpoint handler.
// - Validate Email and Password fields to ensure they are non-empty before processing.
// - Sanitize inputs to prevent injection attacks (though GORM's parameterized queries handle this for database operations).
// - Consider adding additional fields (e.g., two-factor authentication code) for enhanced security.
type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse Struct
// Syntax: type TokenResponse struct { Email string; Role string; Token string; RefreshToken string }
// Description:
// The TokenResponse struct represents the JSON response sent to the client after a successful signin.
// It contains the user's email, role, JWT token, and refresh token. In a JWT system, this struct is used
// to return authentication details to the client, allowing them to use the JWT token for accessing protected
// endpoints and the refresh token to obtain new JWTs when the original expires. The struct uses JSON tags
// to map fields to JSON keys, ensuring proper serialization of the response.
// Fields:
// - Email (string): The authenticated user's email address, included for client convenience.
// - Role (string): The authenticated user's role (e.g., "user" or "admin"), included for client-side logic.
// - Token (string): The JWT token used for authenticating requests to protected endpoints.
// - RefreshToken (string): The refresh token used to obtain a new JWT when the original expires.
// JSON Tags:
// - json:"email": Maps the Email field to the "email" key in the JSON response.
// - json:"role": Maps the Role field to the "role" key in the JSON response.
// - json:"token": Maps the Token field to the "token" key in the JSON response.
// - json:"refresh_token": Maps the RefreshToken field to the "refresh_token" key in the JSON response.
// Usage in Production:
// - Use TokenResponse to structure the /signin endpoint response.
// - Ensure the Token is a valid JWT signed with the HS256 algorithm and a strong secret.
// - Store refresh tokens securely in the database (not implemented here) to validate them later.
// - Avoid including sensitive data (e.g., password) in the response.
// - Consider adding token expiration details (e.g., "expires_at") for client-side handling.
type TokenResponse struct {
	Email        string `json:"email"`
	Role         string `json:"role"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

// GenerateJWT Function
// Syntax: func GenerateJWT(email, role, jwtSecret string) (string, error)
// Description:
// The GenerateJWT function creates a signed JWT token for a user, containing their email, role, expiration
// time, and an "authorized" flag. It uses the HS256 signing method (HMAC with SHA-256) for security and
// signs the token with the provided secret. In a JWT system, this function is called during the signin
// process to generate a token that clients include in the Authorization header for protected endpoints.
// The token expires after 30 minutes, requiring clients to refresh it using a refresh token or re-authenticate.
// Parameters:
// - email (string): The user's email address, included as a claim in the JWT.
// - role (string): The user's role (e.g., "user" or "admin"), included as a claim for access control.
// - jwtSecret (string): The secret key used to sign the JWT, ensuring its integrity and authenticity.
// Returns:
// - string: The signed JWT token as a string (e.g., "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...").
// - error: An error if token signing fails (e.g., invalid secret).
// Mechanics:
//   - Creates a new JWT with HS256 signing method and MapClaims containing email, role, expiration (30 minutes),
//     and an "authorized" flag.
//   - Signs the token with the provided jwtSecret using token.SignedString.
//   - Returns the signed token string or an error if signing fails.
//
// Usage in Production:
// - Call GenerateJWT during the /signin endpoint after successful authentication (via db.AuthenticateUser).
// - Use a strong, random jwtSecret (at least 32 bytes) to prevent token forging.
// - Set a short expiration time (e.g., 30 minutes) to limit the impact of stolen tokens.
// - Store the jwtSecret securely in environment variables or a secrets manager.
// - Log token generation errors for debugging and monitor for repeated failures (e.g., misconfigured secret).
func GenerateJWT(email, role, jwtSecret string) (string, error) {
	// Create a new JWT with HS256 signing method and MapClaims for custom claims.
	// The claims include email, role, expiration time (30 minutes from now), and an "authorized" flag.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":      email,
		"role":       role,
		"exp":        time.Now().Add(30 * time.Minute).Unix(),
		"authorized": true,
	})

	// Sign the token with the provided secret and return the signed string.
	// The secret ensures the token's integrity and authenticity.
	return token.SignedString([]byte(jwtSecret))
}

// GenerateRefreshToken Function
// Syntax: func GenerateRefreshToken(email, jwtSecret string) (string, error)
// Description:
// The GenerateRefreshToken function creates a long-lived refresh token for a user, containing their email
// and an expiration time (7 days). It uses the HS256 signing method for security and signs the token with
// the provided secret. In a JWT system, refresh tokens allow clients to obtain new JWTs without re-entering
// credentials, improving user experience while maintaining security. This implementation does not store
// refresh tokens in the database (a common production practice), so they are validated only by signature
// and expiration.
// Parameters:
// - email (string): The user's email address, included as a claim in the refresh token.
// - jwtSecret (string): The secret key used to sign the refresh token, ensuring its integrity and authenticity.
// Returns:
// - string: The signed refresh token as a string (e.g., "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...").
// - error: An error if token signing fails (e.g., invalid secret).
// Mechanics:
// - Creates a new JWT with HS256 signing method and MapClaims containing email and expiration (7 days).
// - Signs the token with the provided jwtSecret using token.SignedString.
// - Returns the signed token string or an error if signing fails.
// Usage in Production:
// - Call GenerateRefreshToken during the /signin endpoint to provide a refresh token alongside the JWT.
// - Use the same jwtSecret as GenerateJWT for consistency, or a separate secret for refresh tokens.
// - Set a long expiration time (e.g., 7 days) to balance usability and security.
// - Store refresh tokens in the database with a unique identifier and invalidate them on logout or compromise.
// - Implement a /refresh endpoint to validate refresh tokens and issue new JWTs (not implemented here).
func GenerateRefreshToken(email, jwtSecret string) (string, error) {
	// Create a new refresh token with HS256 signing method and MapClaims for email and expiration.
	// The token expires after 7 days, allowing long-term use without re-authentication.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(7 * 24 * time.Hour).Unix(),
	})

	// Sign the token with the provided secret and return the signed string.
	return token.SignedString([]byte(jwtSecret))
}

// IsAuthorized Function
// Syntax: func IsAuthorized(handler http.HandlerFunc, requiredRole, jwtSecret string) http.HandlerFunc
// Description:
// The IsAuthorized function is middleware that verifies a JWT token from the Authorization header and
// checks if the user has the required role (e.g., "admin" for /admin, "user" for /user). It extracts the
// token, validates its signature and expiration, and ensures the role claim matches the required role.
// If valid, it sets the role in the request context and passes the request to the next handler. In a JWT
// system, this middleware secures protected endpoints, ensuring only authorized users with the correct
// role can access them. It’s applied to routes like /admin and /user to enforce role-based access control.
// Parameters:
// - handler (http.HandlerFunc): The next handler to call if the JWT is valid and the role matches.
// - requiredRole (string): The role required to access the endpoint (e.g., "admin" or "user").
// - jwtSecret (string): The secret key used to verify the JWT's signature.
// Returns:
// - http.HandlerFunc: A new handler that wraps the input handler with JWT validation and role checking.
// Mechanics:
// - Checks for a valid Authorization header with "Bearer " prefix.
// - Parses the JWT using jwt.Parse, verifying the HS256 signing method and secret.
// - Validates the token’s signature and expiration.
// - Checks if the role claim matches the requiredRole.
// - Sets the role in the request context using config.RoleContextKey.
// - Calls the next handler if all checks pass, or sends an error response (401 or 403) if they fail.
// Usage in Production:
// - Apply IsAuthorized to protected endpoints in setupRoutes (e.g., /admin, /user).
// - Use a strong, random jwtSecret (at least 32 bytes) to prevent token forging.
// - Log failed authorization attempts for security monitoring (e.g., brute-force or token tampering).
// - Consider adding rate-limiting to prevent repeated unauthorized requests.
// - Handle edge cases like missing or malformed headers gracefully with clear error messages.
func IsAuthorized(handler http.HandlerFunc, requiredRole, jwtSecret string) http.HandlerFunc {
	// Return a new handler that validates the JWT and role before calling the next handler.
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization header and ensure it starts with "Bearer ".
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			// Send a 401 Unauthorized response if the header is missing or invalid.
			sendError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
			return
		}

		// Extract the JWT token by removing the "Bearer " prefix.
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate the JWT using the provided secret.
		// The callback function verifies the signing method and provides the secret for validation.
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				// Return an error if the signing method is not HMAC (HS256).
				return nil, fmt.Errorf("invalid signing method")
			}
			// Provide the secret for signature verification.
			return []byte(jwtSecret), nil
		})

		// Send a 401 Unauthorized response if parsing fails or the token is invalid (e.g., expired).
		if err != nil || !token.Valid {
			sendError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Extract claims and verify the role matches the required role.
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["role"] != requiredRole {
			// Send a 403 Forbidden response if the role is missing or does not match.
			sendError(w, http.StatusForbidden, "Insufficient role permissions")
			return
		}

		// Set the role in the request context for use by the next handler.
		// Uses config.RoleContextKey to avoid key collisions.
		ctx := context.WithValue(r.Context(), config.RoleContextKey, claims["role"])
		// Call the next handler with the updated context.
		handler.ServeHTTP(w, r.WithContext(ctx))
	}
}

// sendError Function
// Syntax: func sendError(w http.ResponseWriter, status int, message string)
// Description:
// The sendError function sends a standardized JSON error response with a specified HTTP status code
// and message. It is used by the IsAuthorized middleware to return errors for invalid JWTs or insufficient
// permissions. In a JWT system, this function ensures consistent error responses for authentication and
// authorization failures, improving client-side error handling and debugging.
// Parameters:
// - w (http.ResponseWriter): The response writer to send the error response.
// - status (int): The HTTP status code (e.g., 401 for Unauthorized, 403 for Forbidden).
// - message (string): The error message to include in the JSON response (e.g., "Invalid or expired token").
// Returns:
// - None (writes directly to the response writer).
// Mechanics:
// - Sets the Content-Type header to "application/json".
// - Sets the HTTP status code using WriteHeader.
// - Encodes a JSON object with a "message" field containing the error message.
// Usage in Production:
// - Use sendError for all error responses in middleware and handlers to ensure consistency.
// - Include clear, user-friendly error messages without exposing sensitive details (e.g., stack traces).
// - Log errors for monitoring and debugging, especially for 401 and 403 responses.
// - Consider adding error codes or additional fields (e.g., "error_code") for client-side handling.
func sendError(w http.ResponseWriter, status int, message string) {
	// Set the Content-Type header to indicate a JSON response.
	w.Header().Set("Content-Type", "application/json")
	// Set the HTTP status code (e.g., 401, 403).
	w.WriteHeader(status)
	// Encode a JSON response with the error message.
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{Message: message})
}

/*
### Summary of auth/auth.go in JWT Authentication
The `auth` package is the core of the JWT-based authentication system, providing:
- **AuthRequest Struct**: Parses the /signin request payload for email and password.
- **TokenResponse Struct**: Structures the /signin response with JWT and refresh tokens.
- **GenerateJWT Function**: Creates short-lived JWT tokens for authenticated requests.
- **GenerateRefreshToken Function**: Creates long-lived refresh tokens for token renewal.
- **IsAuthorized Function**: Middleware to validate JWTs and enforce role-based access control.
- **sendError Function**: Sends standardized JSON error responses for authentication failures.

### Production Use Case Guidance
For developers building a JWT authentication system in Go:
1. **JWT Security**:
   - Use the HS256 signing method (or stronger, like RS256 for asymmetric keys) with a strong, random `jwtSecret` (at least 32 bytes).
   - Store the `jwtSecret` in environment variables or a secrets manager, never in code.
   - Set short JWT expiration times (e.g., 15-30 minutes) to limit the impact of stolen tokens.
   - Implement refresh token storage in the database with invalidation mechanisms (e.g., on logout).
2. **Role-Based Access Control**:
   - Use `IsAuthorized` middleware to enforce role-based access for all protected endpoints.
   - Validate roles strictly (e.g., "admin" vs. "user") and return clear 403 errors for mismatches.
   - Consider adding more granular permissions (e.g., scopes) for complex access control.
3. **Error Handling**:
   - Use `sendError` for consistent error responses across all endpoints.
   - Log authentication failures (401, 403) to detect brute-force attacks or misconfigurations.
   - Avoid exposing sensitive details (e.g., token contents, stack traces) in error responses.
4. **Scalability**:
   - Optimize JWT parsing for high-traffic endpoints by caching parsed tokens (if applicable).
   - Implement rate-limiting on /signin to prevent brute-force attacks.
   - Use a /refresh endpoint to handle refresh tokens, validating them against a database.
5. **Testing**:
   - Test JWT generation and validation with various edge cases (e.g., expired tokens, invalid signatures).
   - Mock the `IsAuthorized` middleware in unit tests to isolate handler logic.
   - Use tools like `curl` or Postman to verify token-based access to protected endpoints.
6. **Monitoring**:
   - Log token generation and validation events for auditing.
   - Monitor 401 and 403 errors to detect security issues or user errors.
   - Use metrics (e.g., Prometheus) to track authentication latency and failure rates.
*/
