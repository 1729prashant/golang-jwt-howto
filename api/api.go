package api

// The api package sets up the HTTP routing and middleware for the JWT-based authentication system.
// It uses the Gorilla Mux router to define endpoints for user signup, signin, and protected routes
// (e.g., /admin, /user), and integrates CORS middleware to allow secure cross-origin requests from
// trusted clients. The package defines a Router struct to encapsulate the Gorilla Mux router,
// configuration, and database instance, providing a clean interface for starting the HTTP server
// and handling requests. In a JWT system, this package is responsible for defining the API endpoints,
// securing them with JWT authentication middleware, and ensuring cross-origin requests are handled
// safely. For production, it ensures scalable routing, secure CORS configuration, and integration
// with the database and JWT authentication logic.

import (
	"net/http"

	"golang-jwt-howto/config"
	"golang-jwt-howto/db"

	"github.com/gorilla/mux"
)

// Router Struct
// Syntax: type Router struct { *mux.Router; config *config.Config; db *db.DB }
// Description:
// The Router struct encapsulates the Gorilla Mux router, application configuration, and database instance
// to provide a unified interface for handling HTTP requests in the JWT authentication system. It embeds
// the *mux.Router type to leverage Gorilla Mux's powerful routing capabilities, such as path variables
// and middleware chaining. The struct holds references to the Config and DB instances to access settings
// (e.g., CORSAllowedOrigin, JWTSecret) and perform database operations (e.g., user creation, authentication).
// In a JWT system, the Router struct is used to define and secure endpoints like /signup, /signin, /admin,
// and /user, and to start the HTTP server. It ensures that all request handling is centralized and
// configured with the necessary dependencies.
// Fields:
//   - *mux.Router: The embedded Gorilla Mux router instance, providing methods to define routes and middleware.
//   - config (*config.Config): The application configuration, containing settings like JWTSecret, CORSAllowedOrigin,
//     and DatabaseURL.
//   - db (*db.DB): The database instance, used for user-related operations like signup and authentication.
//
// Usage in Production:
// - Initialize with NewRouter to set up routes and middleware.
// - Use Start to run the HTTP server on a specified port.
// - Ensure the Config and DB instances are properly initialized before creating the Router.
// - Leverage Gorilla Mux's features (e.g., path prefixes, regex routing) for complex API designs.
// - Secure endpoints with middleware (e.g., JWT authentication, CORS) to protect sensitive operations.
type Router struct {
	*mux.Router
	config *config.Config
	db     *db.DB
}

// NewRouter Function
// Syntax: func NewRouter(cfg *config.Config, db *db.DB) *Router
// Description:
// The NewRouter function creates and configures a new Router instance with the provided configuration
// and database instance. It initializes a Gorilla Mux router, stores the configuration and database,
// and calls setupRoutes to define the application's HTTP endpoints and middleware. In a JWT system,
// this function is called during application startup to set up all API routes, including public endpoints
// (e.g., /, /signup, /signin) and protected endpoints (e.g., /admin, /user) secured with JWT middleware.
// It ensures that the router is fully configured with CORS and authentication middleware before handling
// requests.
// Parameters:
//   - cfg (*config.Config): The application configuration, containing settings like JWTSecret, CORSAllowedOrigin,
//     and DatabaseURL.
//   - db (*db.DB): The database instance for user-related operations.
//
// Returns:
// - *Router: A pointer to the initialized Router struct with configured routes and middleware.
// Mechanics:
// - Creates a new Router struct with a fresh Gorilla Mux router instance.
// - Stores the provided Config and DB instances in the struct.
// - Calls setupRoutes (not shown in this file, likely in handlers.go) to define endpoints and middleware.
// - Returns the configured Router instance.
// Usage in Production:
// - Call NewRouter during application startup (e.g., in main.go) after loading Config and initializing DB.
// - Pass the Router to the HTTP server to handle incoming requests.
// - Ensure setupRoutes defines all necessary endpoints and secures them with appropriate middleware.
// - Use Gorilla Mux's StrictSlash(true) for consistent URL handling (e.g., redirect /route to /route/).
// - Monitor route performance and consider rate-limiting for public endpoints like /signup and /signin.
func NewRouter(cfg *config.Config, db *db.DB) *Router {
	// Initialize a new Router struct with a fresh Gorilla Mux router.
	// The Router struct embeds mux.Router to inherit its routing capabilities.
	rtr := &Router{
		Router: mux.NewRouter(),
		config: cfg,
		db:     db,
	}
	// Set up all API routes and middleware by calling setupRoutes.
	// This configures endpoints like /signup, /signin, /admin, and /user, and applies CORS and JWT middleware.
	rtr.setupRoutes()
	// Return the configured Router instance.
	return rtr
}

// Start Function
// Syntax: func (rtr *Router) Start(addr string) error
// Description:
// The Start function launches the HTTP server to listen for incoming requests on the specified address
// (e.g., ":8080"). It uses the embedded Gorilla Mux router to handle requests according to the configured
// routes and middleware. In a JWT system, this function starts the server that exposes endpoints for
// user signup, signin, and protected routes, enabling clients to interact with the authentication system.
// It’s called during application startup to make the API available.
// Parameters:
// - addr (string): The address and port to listen on (e.g., ":8080").
// Returns:
// - error: An error if the server fails to start (e.g., port already in use), wrapped with context.
// Mechanics:
// - Calls http.ListenAndServe to start the HTTP server with the Router’s mux.Router as the handler.
// - Passes the provided address to specify the listening port.
// - Returns any errors encountered during server startup.
// Usage in Production:
// - Call Start in main.go with the port from Config (e.g., cfg.Port).
// - Ensure the port is free to avoid "address already in use" errors.
// - Use a production-grade server setup (e.g., graceful shutdown, HTTPS with TLS) for robustness.
// - Log server startup and errors for monitoring and debugging.
// - Consider deploying behind a reverse proxy (e.g., Nginx) for load balancing and SSL termination.
func (rtr *Router) Start(addr string) error {
	// Start the HTTP server using the embedded Gorilla Mux router to handle requests.
	// The addr parameter specifies the host and port (e.g., ":8080").
	return http.ListenAndServe(addr, rtr.Router)
}

// corsMiddleware Function
// Syntax: func (rtr *Router) corsMiddleware(next http.Handler) http.Handler
// Description:
// The corsMiddleware function configures Cross-Origin Resource Sharing (CORS) settings to allow secure
// cross-origin requests from trusted clients. It sets HTTP headers to specify allowed origins, methods,
// and headers, and handles preflight OPTIONS requests. In a JWT system, this middleware ensures that
// client-side applications (e.g., a React frontend running on a different domain) can access the API
// securely, particularly for endpoints like /signup, /signin, /admin, and /user. It’s applied globally
// to all routes to enforce consistent CORS policies.
// Parameters:
//   - next (http.Handler): The next handler in the middleware chain to process the request after CORS headers
//     are set.
//
// Returns:
// - http.Handler: A new handler that applies CORS headers and delegates to the next handler.
// Mechanics:
// - Sets the Access-Control-Allow-Origin header to the configured CORSAllowedOrigin (e.g., "http://localhost:3000").
// - Sets Access-Control-Allow-Methods to allow GET, POST, and OPTIONS requests.
// - Sets Access-Control-Allow-Headers to allow Content-Type and Authorization headers (for JWT tokens).
// - Handles OPTIONS requests (preflight) by returning a 200 OK status without further processing.
// - Delegates to the next handler for non-OPTIONS requests.
// Usage in Production:
//   - Apply corsMiddleware to all routes in setupRoutes to ensure consistent CORS handling.
//   - Set CORSAllowedOrigin to the production client domain (e.g., "https://yourapp.com") to prevent
//     unauthorized cross-origin access.
//   - Validate CORS headers to ensure only necessary methods and headers are allowed.
//   - Log CORS-related errors or invalid requests for security monitoring.
//   - Consider using a dedicated CORS library (e.g., github.com/rs/cors) for more complex CORS policies.
func (rtr *Router) corsMiddleware(next http.Handler) http.Handler {
	// Return a new HTTP handler that applies CORS headers before delegating to the next handler.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers to allow requests from the configured origin (e.g., "http://localhost:3000").
		// This ensures only trusted clients can access the API.
		w.Header().Set("Access-Control-Allow-Origin", rtr.config.CORSAllowedOrigin)
		// Allow GET, POST, and OPTIONS methods for API operations and preflight requests.
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		// Allow Content-Type (for JSON payloads) and Authorization (for JWT tokens) headers.
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")

		// Handle preflight OPTIONS requests sent by browsers to check CORS policies.
		// Return 200 OK immediately without processing further.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Delegate to the next handler in the chain for non-OPTIONS requests.
		next.ServeHTTP(w, r)
	})
}

// index Function
// Syntax: func (rtr *Router) index(w http.ResponseWriter, r *http.Request)
// Description:
// The index function handles requests to the root endpoint ("/") of the API, serving as a simple
// public endpoint to verify that the server is running. It writes a static string, "HOME PUBLIC INDEX PAGE",
// to the HTTP response. In a JWT system, this endpoint is unauthenticated and accessible to all clients,
// providing a basic health check or welcome message. It’s a minimal example of a public endpoint, not
// requiring JWT authentication or database access.
// Parameters:
// - w (http.ResponseWriter): The response writer to send the HTTP response.
// - r (*http.Request): The incoming HTTP request.
// Returns:
// - None (writes directly to the response writer).
// Mechanics:
// - Writes the string "HOME PUBLIC INDEX PAGE" as a byte slice to the response writer.
// - Implicitly returns a 200 OK status unless an error occurs during writing.
// Usage in Production:
// - Use the index endpoint as a health check for monitoring tools (e.g., Kubernetes liveness probes).
// - Consider adding dynamic content or version information to the response for debugging.
// - Ensure the endpoint is publicly accessible but rate-limited to prevent abuse.
// - Log requests to the index endpoint for traffic monitoring, but avoid logging sensitive data.
func (rtr *Router) index(w http.ResponseWriter, r *http.Request) {
	// Write a static response to indicate the server is running and accessible.
	// This is a simple public endpoint not requiring authentication.
	w.Write([]byte("HOME PUBLIC INDEX PAGE"))
}

/*
### Summary of api/api.go in JWT Authentication
The `api` package is responsible for setting up the HTTP routing and middleware for the JWT-based authentication system. It provides:
- **Router Struct**: Encapsulates the Gorilla Mux router, configuration, and database for centralized request handling.
- **NewRouter Function**: Initializes the router with all API endpoints and middleware.
- **Start Function**: Launches the HTTP server to handle incoming requests.
- **corsMiddleware Function**: Configures CORS to allow secure cross-origin requests from trusted clients.
- **index Function**: Provides a simple public endpoint for health checks or verification.

### Production Use Case Guidance
For developers building a JWT authentication system in Go:
1. **Routing**:
   - Use Gorilla Mux for its flexibility in defining routes, middleware, and path variables.
   - Organize routes in a separate `setupRoutes` function (likely in `handlers.go`) for clarity.
   - Enable `StrictSlash(true)` on the router for consistent URL handling (e.g., redirect `/route` to `/route/`).
2. **Security**:
   - Apply `corsMiddleware` to all routes to enforce strict CORS policies.
   - Set `CORSAllowedOrigin` to specific production domains (e.g., `https://yourapp.com`) to prevent unauthorized access.
   - Use JWT middleware (likely in `handlers.go`) to secure protected endpoints like `/admin` and `/user`.
   - Validate all incoming requests for proper headers (e.g., `Content-Type: application/json`, `Authorization: Bearer <token>`).
3. **Scalability**:
   - Configure the HTTP server with timeouts (e.g., `ReadTimeout`, `WriteTimeout`) for resilience.
   - Deploy behind a reverse proxy (e.g., Nginx, Traefik) for load balancing, SSL termination, and rate-limiting.
   - Monitor route performance and set up rate-limiting for public endpoints (`/signup`, `/signin`) to prevent abuse.
4. **Error Handling**:
   - Log server startup errors (e.g., port conflicts) and notify administrators.
   - Handle CORS preflight requests correctly to avoid client-side errors.
   - Return meaningful HTTP status codes (e.g., 401 for unauthorized, 403 for forbidden) in middleware and handlers.
5. **Testing**:
   - Test all endpoints with tools like `curl` or Postman to verify behavior.
   - Mock the Router struct in unit tests to isolate HTTP handling logic.
   - Use a test-specific `CORSAllowedOrigin` to simulate client access in development.
6. **Monitoring**:
   - Log all requests (excluding sensitive data like passwords or tokens) for auditing.
   - Set up health check endpoints (like `index`) for monitoring tools to verify server availability.
   - Use metrics (e.g., Prometheus) to track request latency and error rates for each endpoint.
*/
