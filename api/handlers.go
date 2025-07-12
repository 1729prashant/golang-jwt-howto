package api

// The api package (handlers.go) defines the HTTP handlers and routing configuration for the JWT-based
// authentication system. It extends the Router struct (defined in api.go) by implementing the setupRoutes
// function to configure API endpoints and middleware, and provides handler functions for user signup,
// signin, and protected endpoints (/admin, /user). The package integrates with the auth package for JWT
// generation and validation, the db package for user management, and the config package for settings like
// JWTSecret and CORSAllowedOrigin. In a JWT system, this file handles incoming HTTP requests, validates
// inputs, performs authentication, and enforces role-based access control. For production, it ensures secure
// request handling, consistent error responses, and proper middleware application for scalability and security.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"golang-jwt-howto/auth"
	"golang-jwt-howto/config"
	"golang-jwt-howto/db"
)

// setupRoutes Function
// Syntax: func (rtr *Router) setupRoutes()
// Description:
// The setupRoutes function configures the HTTP routes and middleware for the application's API using
// the Gorilla Mux router. It applies the CORS middleware globally to all routes and defines endpoints
// for the root ("/"), user signup (/signup), signin (/signin), and protected admin (/admin) and user
// (/user) routes. The protected routes are secured with the auth.IsAuthorized middleware to enforce
// JWT-based authentication and role-based access control. In a JWT system, this function is critical
// for setting up the API's structure, ensuring that public endpoints are accessible and protected
// endpoints require valid JWTs with appropriate roles.
// Parameters:
// - None (operates on the receiver *Router).
// Returns:
// - None (configures the Router's routes directly).
// Mechanics:
//   - Applies the corsMiddleware to all routes to handle cross-origin requests securely.
//   - Defines the root endpoint ("/") as a public GET route handled by index.
//   - Defines /signup and /signin as public POST routes handled by signUp and signIn.
//   - Defines /admin and /user as protected GET routes, wrapped with IsAuthorized middleware to require
//     "admin" and "user" roles, respectively.
//   - Uses rtr.config.JWTSecret for JWT validation in protected routes.
//
// Usage in Production:
// - Call setupRoutes during Router initialization (in NewRouter) to configure all API endpoints.
// - Ensure CORS middleware is applied first to handle preflight OPTIONS requests correctly.
// - Secure protected endpoints with IsAuthorized middleware, specifying the required role.
// - Validate route definitions to avoid conflicts (e.g., overlapping paths).
// - Log route setup errors or warnings for debugging, and monitor endpoint usage for performance.
func (rtr *Router) setupRoutes() {
	// Apply CORS middleware to all routes to enable secure cross-origin requests.
	// This ensures clients (e.g., a frontend at http://localhost:3000) can access the API.
	rtr.Router.Use(rtr.corsMiddleware)

	// Define the root endpoint ("/") as a public GET route.
	// This is handled by the index function and serves as a health check or welcome page.
	rtr.Router.HandleFunc("/", rtr.index).Methods(http.MethodGet)

	// Define the /signup endpoint as a public POST route.
	// This allows clients to register new users by sending user details (name, email, password, role).
	rtr.Router.HandleFunc("/signup", rtr.signUp).Methods(http.MethodPost)

	// Define the /signin endpoint as a public POST route.
	// This allows clients to authenticate and receive JWT and refresh tokens.
	rtr.Router.HandleFunc("/signin", rtr.signIn).Methods(http.MethodPost)

	// Define the /admin endpoint as a protected GET route.
	// The IsAuthorized middleware ensures only users with the "admin" role can access it.
	rtr.Router.HandleFunc("/admin", auth.IsAuthorized(rtr.adminIndex, "admin", rtr.config.JWTSecret)).Methods(http.MethodGet)

	// Define the /user endpoint as a protected GET route.
	// The IsAuthorized middleware ensures only users with the "user" role can access it.
	rtr.Router.HandleFunc("/user", auth.IsAuthorized(rtr.userIndex, "user", rtr.config.JWTSecret)).Methods(http.MethodGet)
}

// signUp Function
// Syntax: func (rtr *Router) signUp(w http.ResponseWriter, r *http.Request)
// Description:
// The signUp function handles HTTP POST requests to the /signup endpoint, allowing clients to register
// new users. It decodes the JSON request body into a db.User struct, validates required fields (email
// and password), and creates the user in the database using db.CreateUser. If successful, it returns
// the created user's details with a 201 Created status. In a JWT system, this function is the entry
// point for user registration, enabling clients to create accounts that can later be used for
// authentication via /signin. It enforces input validation and handles errors like duplicate emails.
// Parameters:
// - w (http.ResponseWriter): The response writer to send the HTTP response.
// - r (*http.Request): The incoming HTTP request containing the user details in the JSON body.
// Returns:
// - None (writes directly to the response writer with a JSON response or error).
// Mechanics:
// - Decodes the JSON request body into a db.User struct (name, email, password, role).
// - Validates that email and password are non-empty, returning a 400 Bad Request if invalid.
// - Adds the database instance to the request context using config.DBContextKey.
// - Calls db.CreateUser to store the user, handling errors like duplicate emails (409 Conflict).
// - Logs internal errors using slog for debugging.
// - Returns a 201 Created response with the user details (excluding password for security).
// Usage in Production:
// - Use signUp as the handler for the /signup POST endpoint.
// - Validate and sanitize input data to prevent injection attacks (GORM's parameterized queries help here).
// - Return clear error messages for client-side handling (e.g., "Email already in use").
// - Log errors for monitoring and debugging, but avoid exposing sensitive details in responses.
// - Consider adding rate-limiting to prevent abuse (e.g., bulk user creation).
// - Enhance validation for email format, password strength, and role values (e.g., restrict to "user" or "admin").
func (rtr *Router) signUp(w http.ResponseWriter, r *http.Request) {
	// Decode the JSON request body into a db.User struct to extract user details.
	var user db.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		// Return a 400 Bad Request if the JSON is invalid or malformed.
		rtr.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate that email and password are provided, as they are required for user creation.
	if user.Email == "" || user.Password == "" {
		// Return a 400 Bad Request if either field is missing.
		rtr.sendError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	// Add the database instance to the request context for thread-safe access.
	// This allows db.CreateUser to retrieve the database without global variables.
	ctx := context.WithValue(r.Context(), config.DBContextKey, rtr.db)

	// Create the user in the database, hashing the password and checking for duplicates.
	if err := db.CreateUser(ctx, user); err != nil {
		// Handle duplicate email errors specifically with a 409 Conflict response.
		if strings.Contains(err.Error(), "email already exists") {
			rtr.sendError(w, http.StatusConflict, "Email already in use")
			return
		}
		// Log other errors for debugging and return a 500 Internal Server Error.
		slog.Error("Failed to create user", "error", err)
		rtr.sendError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Set the Content-Type header to indicate a JSON response.
	w.Header().Set("Content-Type", "application/json")
	// Set the status code to 201 Created to indicate successful user creation.
	w.WriteHeader(http.StatusCreated)
	// Encode the created user as JSON (password is typically cleared by db.CreateUser for security).
	json.NewEncoder(w).Encode(user)
}

// signIn Function
// Syntax: func (rtr *Router) signIn(w http.ResponseWriter, r *http.Request)
// Description:
// The signIn function handles HTTP POST requests to the /signin endpoint, authenticating users and
// issuing JWT and refresh tokens. It decodes the JSON request body into an auth.AuthRequest struct,
// verifies the credentials using db.AuthenticateUser, and generates tokens using auth.GenerateJWT
// and auth.GenerateRefreshToken. If successful, it returns a JSON response with the user's email,
// role, JWT token, and refresh token. In a JWT system, this function is the entry point for user
// authentication, enabling clients to obtain tokens for accessing protected endpoints.
// Parameters:
// - w (http.ResponseWriter): The response writer to send the HTTP response.
// - r (*http.Request): The incoming HTTP request containing the email and password in the JSON body.
// Returns:
// - None (writes directly to the response writer with a JSON response or error).
// Mechanics:
// - Decodes the JSON request body into an auth.AuthRequest struct (email, password).
// - Adds the database instance to the request context using config.DBContextKey.
// - Calls db.AuthenticateUser to verify the email and password, returning a 401 Unauthorized if invalid.
// - Generates a JWT token (30-minute expiration) and refresh token (7-day expiration) using the user's email and role.
// - Logs token generation errors for debugging.
// - Returns a 200 OK response with an auth.TokenResponse containing the tokens and user details.
// Usage in Production:
// - Use signIn as the handler for the /signin POST endpoint.
// - Validate and sanitize input data to prevent injection attacks.
// - Return clear error messages for invalid credentials (e.g., "Invalid email or password").
// - Log authentication failures to detect brute-force attempts.
// - Implement rate-limiting to prevent abuse of the /signin endpoint.
// - Consider adding two-factor authentication or refresh token storage for enhanced security.
func (rtr *Router) signIn(w http.ResponseWriter, r *http.Request) {
	// Decode the JSON request body into an auth.AuthRequest struct to extract email and password.
	var authReq auth.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		// Return a 400 Bad Request if the JSON is invalid or malformed.
		rtr.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Add the database instance to the request context for thread-safe access.
	ctx := context.WithValue(r.Context(), config.DBContextKey, rtr.db)

	// Authenticate the user by verifying the email and password against the database.
	user, err := db.AuthenticateUser(ctx, authReq.Email, authReq.Password)
	if err != nil {
		// Return a 401 Unauthorized if credentials are invalid.
		rtr.sendError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Generate a JWT token with the user's email and role, expiring in 30 minutes.
	token, err := auth.GenerateJWT(user.Email, user.Role, rtr.config.JWTSecret)
	if err != nil {
		// Log the error for debugging and return a 500 Internal Server Error.
		slog.Error("Failed to generate JWT", "error", err)
		rtr.sendError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Generate a refresh token with the user's email, expiring in 7 days.
	refreshToken, err := auth.GenerateRefreshToken(user.Email, rtr.config.JWTSecret)
	if err != nil {
		// Log the error for debugging and return a 500 Internal Server Error.
		slog.Error("Failed to generate refresh token", "error", err)
		rtr.sendError(w, http.StatusInternalServerError, "Failed to generate refresh token")
		return
	}

	// Create a response struct with the user's email, role, and tokens.
	response := auth.TokenResponse{
		Email:        user.Email,
		Role:         user.Role,
		Token:        token,
		RefreshToken: refreshToken,
	}

	// Set the Content-Type header to indicate a JSON response.
	w.Header().Set("Content-Type", "application/json")
	// Encode the response as JSON, including the JWT and refresh tokens.
	json.NewEncoder(w).Encode(response)
}

// adminIndex Function
// Syntax: func (rtr *Router) adminIndex(w http.ResponseWriter, r *http.Request)
// Description:
// The adminIndex function handles HTTP GET requests to the /admin endpoint, serving as a protected
// endpoint for users with the "admin" role. It writes a simple welcome message ("Welcome, Admin") to
// the response. In a JWT system, this endpoint is secured by the auth.IsAuthorized middleware, which
// ensures only users with a valid JWT and the "admin" role can access it. This function demonstrates
// a basic protected endpoint, typically used for administrative actions.
// Parameters:
// - w (http.ResponseWriter): The response writer to send the HTTP response.
// - r (*http.Request): The incoming HTTP request, with the role set in the context by middleware.
// Returns:
// - None (writes directly to the response writer with a text response).
// Mechanics:
// - Writes the string "Welcome, Admin" to the response writer.
// - Implicitly returns a 200 OK status unless an error occurs during writing.
// - Relies on auth.IsAuthorized middleware to verify the JWT and role before execution.
// Usage in Production:
// - Use adminIndex for admin-specific functionality (e.g., user management, system settings).
// - Secure the endpoint with auth.IsAuthorized middleware, specifying the "admin" role.
// - Log access to the /admin endpoint for auditing, as it’s sensitive.
// - Consider adding dynamic content (e.g., admin dashboard data) instead of a static message.
// - Monitor for unauthorized access attempts (handled by middleware) to detect security issues.
func (rtr *Router) adminIndex(w http.ResponseWriter, r *http.Request) {
	// Write a welcome message to indicate successful access to the admin endpoint.
	// The middleware ensures only users with the "admin" role reach this point.
	w.Write([]byte("Welcome, Admin"))
}

// userIndex Function
// Syntax: func (rtr *Router) userIndex(w http.ResponseWriter, r *http.Request)
// Description:
// The userIndex function handles HTTP GET requests to the /user endpoint, serving as a protected
// endpoint for users with the "user" role. It writes a simple welcome message ("Welcome, User") to
// the response. In a JWT system, this endpoint is secured by the auth.IsAuthorized middleware, which
// ensures only users with a valid JWT and the "user" role can access it. This function demonstrates
// a basic protected endpoint, typically used for user-specific actions.
// Parameters:
// - w (http.ResponseWriter): The response writer to send the HTTP response.
// - r (*http.Request): The incoming HTTP request, with the role set in the context by middleware.
// Returns:
// - None (writes directly to the response writer with a text response).
// Mechanics:
// - Writes the string "Welcome, User" to the response writer.
// - Implicitly returns a 200 OK status unless an error occurs during writing.
// - Relies on auth.IsAuthorized middleware to verify the JWT and role before execution.
// Usage in Production:
// - Use userIndex for user-specific functionality (e.g., profile management, user data).
// - Secure the endpoint with auth.IsAuthorized middleware, specifying the "user" role.
// - Log access to the /user endpoint for auditing, as it’s user-specific.
// - Consider adding dynamic content (e.g., user profile data) instead of a static message.
// - Monitor for unauthorized access attempts (handled by middleware) to detect security issues.
func (rtr *Router) userIndex(w http.ResponseWriter, r *http.Request) {
	// Write a welcome message to indicate successful access to the user endpoint.
	// The middleware ensures only users with the "user" role reach this point.
	w.Write([]byte("Welcome, User"))
}

// sendError Function
// Syntax: func (rtr *Router) sendError(w http.ResponseWriter, status int, message string)
// Description:
// The sendError function sends a standardized JSON error response with a specified HTTP status code
// and message. It is used by the signUp and signIn handlers (and potentially others) to return errors
// for invalid requests, authentication failures, or server issues. In a JWT system, this function
// ensures consistent error responses across endpoints, improving client-side error handling and debugging.
// Parameters:
// - w (http.ResponseWriter): The response writer to send the error response.
// - status (int): The HTTP status code (e.g., 400 for Bad Request, 401 for Unauthorized, 409 for Conflict).
// - message (string): The error message to include in the JSON response (e.g., "Invalid request body").
// Returns:
// - None (writes directly to the response writer with a JSON error response).
// Mechanics:
// - Sets the Content-Type header to "application/json".
// - Sets the HTTP status code using WriteHeader.
// - Encodes a JSON object with a "message" field containing the error message.
// Usage in Production:
// - Use sendError for all error responses in handlers to ensure consistency.
// - Include clear, user-friendly error messages without exposing sensitive details (e.g., stack traces).
// - Log errors (using slog) for monitoring and debugging, especially for 500 Internal Server Errors.
// - Consider adding error codes or additional fields (e.g., "error_code") for client-side handling.
func (rtr *Router) sendError(w http.ResponseWriter, status int, message string) {
	// Set the Content-Type header to indicate a JSON response.
	w.Header().Set("Content-Type", "application/json")
	// Set the HTTP status code (e.g., 400, 401, 409, 500).
	w.WriteHeader(status)
	// Encode a JSON response with the error message.
	json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{Message: message})
}

/*
### Summary of api/handlers.go in JWT Authentication
The `api/handlers.go` file is the core of the application's HTTP request handling, providing:
- **setupRoutes Function**: Configures all API endpoints and applies CORS middleware globally.
- **signUp Function**: Handles user registration, validating inputs and creating users in the database.
- **signIn Function**: Authenticates users and issues JWT and refresh tokens.
- **adminIndex Function**: Serves a protected endpoint for admin users, secured by JWT middleware.
- **userIndex Function**: Serves a protected endpoint for regular users, secured by JWT middleware.
- **sendError Function**: Provides consistent JSON error responses for all handlers.

### Production Use Case Guidance
For developers building a JWT authentication system in Go:
1. **Endpoint Security**:
   - Secure protected endpoints (/admin, /user) with `auth.IsAuthorized` middleware, specifying the required role.
   - Use a strong, random `JWTSecret` (at least 32 bytes) for token signing and verification.
   - Validate all input data (e.g., email, password) to prevent injection attacks, leveraging GORM's parameterized queries.
2. **Error Handling**:
   - Use `sendError` for consistent error responses with appropriate HTTP status codes (400, 401, 409, 500).
   - Log errors (using `slog`) for monitoring, especially for 500 Internal Server Errors and authentication failures.
   - Avoid exposing sensitive details (e.g., database errors, stack traces) in responses.
3. **Scalability**:
   - Apply rate-limiting to public endpoints (/signup, /signin) to prevent abuse (e.g., brute-force attacks).
   - Optimize database queries in `signUp` and `signIn` by ensuring indexes (e.g., on email) are used.
   - Use connection pooling (configured in `db.go`) to handle high traffic.
4. **CORS Configuration**:
   - Ensure `corsMiddleware` (applied in `setupRoutes`) restricts `CORSAllowedOrigin` to trusted domains in production.
   - Handle preflight OPTIONS requests correctly to support client-side applications.
5. **Testing**:
   - Test all endpoints with tools like `curl` or Postman to verify behavior (e.g., signup, signin, protected routes).
   - Mock the `Router` struct and database in unit tests to isolate handler logic.
   - Use a test-specific database or truncate tables to avoid polluting production data.
6. **Monitoring**:
   - Log all requests and errors (using `slog`) for auditing and debugging.
   - Monitor 401 Unauthorized and 409 Conflict errors to detect user errors or security issues.
   - Use metrics (e.g., Prometheus) to track endpoint latency and error rates.
*/
