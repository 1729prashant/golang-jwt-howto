package main

// The main package serves as the entry point for the JWT-based authentication system.
// It initializes the application's dependencies (configuration, database, router, and logger),
// performs database migrations, and starts the HTTP server. The package defines an App struct
// to hold application-wide dependencies and provides functions to initialize and run the application.
// In a JWT system, main.go orchestrates the startup process, ensuring that the configuration is loaded,
// the database is connected and migrated, and the HTTP server is ready to handle requests for
// user signup, signin, and protected endpoints. For production, it ensures robust initialization,
// error handling, and logging to support a secure and scalable API.

import (
	"log/slog"
	"os"

	"jwt-practice/api"
	"jwt-practice/config"
	"jwt-practice/db"
)

// App Struct
// Syntax: type App struct { DB *db.DB; Router *api.Router; Config *config.Config; Logger *slog.Logger }
// Description:
// The App struct centralizes the application's core dependencies, including the database instance,
// HTTP router, configuration settings, and logger. It provides a single point of access for all
// components needed to run the JWT authentication system, facilitating dependency injection and
// ensuring that dependencies are properly initialized before use. In a JWT system, the App struct
// ties together the database (for user storage), router (for handling HTTP requests), configuration
// (for settings like JWTSecret and Port), and logger (for monitoring and debugging).
// Fields:
// - DB (*db.DB): The database instance used for user-related operations (e.g., signup, authentication).
// - Router (*api.Router): The HTTP router that defines and handles API endpoints (e.g., /signup, /signin).
// - Config (*config.Config): The application configuration, containing settings like DatabaseURL, JWTSecret, and Port.
// - Logger (*slog.Logger): The structured logger for logging application events and errors.
// Usage in Production:
// - Initialize the App struct during startup using newApp to ensure all dependencies are properly set up.
// - Pass the App struct (or its fields) to components that need access to the database, router, or configuration.
// - Use the Logger for structured logging to monitor application health and debug issues.
// - Ensure all fields are non-nil before starting the server to avoid runtime errors.
// - Consider adding additional fields (e.g., metrics client, shutdown handler) for production-grade applications.
type App struct {
	DB     *db.DB
	Router *api.Router
	Config *config.Config
	Logger *slog.Logger
}

// newApp Function
// Syntax: func newApp() (*App, error)
// Description:
// The newApp function initializes the application by creating and configuring its core dependencies.
// It sets up a structured logger, loads the configuration from environment variables, establishes
// a database connection, and initializes the HTTP router. In a JWT system, this function is called
// at startup to prepare the application for handling authentication requests (signup, signin) and
// protected endpoint access (/admin, /user). It ensures that all dependencies are properly initialized
// before the server starts, with errors propagated to the caller for handling.
// Parameters:
// - None
// Returns:
// - *App: A pointer to the initialized App struct containing all dependencies.
// - error: An error if any initialization step fails (e.g., configuration loading, database connection).
// Mechanics:
// - Creates a JSON-structured logger using slog.New with os.Stdout as the output.
// - Loads the configuration using config.Load, which reads environment variables from a .env file.
// - Initializes the database connection using db.New with the DatabaseURL and DBSchema from the configuration.
// - Creates the HTTP router using api.NewRouter with the configuration and database instance.
// - Returns the App struct with all dependencies or an error if any step fails.
// Usage in Production:
// - Call newApp during application startup to initialize dependencies.
// - Handle errors by logging them and exiting the application to prevent running in an invalid state.
// - Use a structured logger (slog) for consistent, machine-readable logs.
// - Ensure the .env file or environment variables are set correctly to avoid configuration errors.
// - Consider adding retry logic for database connections to handle transient failures in production.
func newApp() (*App, error) {
	// Create a structured JSON logger that outputs to stdout.
	// The logger uses slog's JSONHandler for machine-readable, structured logging.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Load the application configuration from environment variables (e.g., .env file).
	// This includes DatabaseURL, JWTSecret, Port, CORSAllowedOrigin, and DBSchema.
	cfg, err := config.Load()
	if err != nil {
		// Return the error to the caller without logging, as the logger is not yet available.
		return nil, err
	}

	// Initialize the database connection using the DatabaseURL and DBSchema from the configuration.
	// This establishes a connection to PostgreSQL and configures connection pooling.
	dbInstance, err := db.New(cfg.DatabaseURL, cfg.DBSchema)
	if err != nil {
		// Return the error to the caller without logging, as the logger is available but the error will be logged in main.
		return nil, err
	}

	// Create the HTTP router with the configuration and database instance.
	// This sets up all API endpoints (/signup, /signin, /admin, /user) and middleware (CORS, JWT).
	router := api.NewRouter(cfg, dbInstance)

	// Return the initialized App struct with all dependencies.
	return &App{
		DB:     dbInstance,
		Router: router,
		Config: cfg,
		Logger: logger,
	}, nil
}

// main Function
// Syntax: func main()
// Description:
// The main function is the entry point of the application, responsible for initializing and running
// the JWT authentication system. It creates the App struct, performs database migrations, and starts
// the HTTP server. In a JWT system, this function orchestrates the startup process, ensuring that
// the database schema is ready, the server is running, and all dependencies are properly configured.
// If any step fails (e.g., initialization, migrations, server startup), it logs the error and exits
// with a non-zero status code to indicate failure.
// Parameters:
// - None
// Returns:
// - None (runs the application and exits on error).
// Mechanics:
// - Calls newApp to initialize the App struct with all dependencies.
// - Logs and exits if initialization fails.
// - Runs database migrations using app.DB.Migrate to ensure the users table and indexes are created.
// - Logs and exits if migrations fail.
// - Logs a startup message with the server port.
// - Starts the HTTP server using app.Router.Start, listening on the configured port.
// - Logs and exits if the server fails to start (e.g., port already in use).
// Usage in Production:
// - Ensure main is the only entry point, keeping it minimal to focus on startup logic.
// - Handle errors by logging them with app.Logger and exiting with os.Exit(1) to signal failure.
// - Run migrations before starting the server to ensure the database schema is ready.
// - Use a production-grade server setup with timeouts, graceful shutdown, and HTTPS.
// - Deploy behind a reverse proxy (e.g., Nginx) for load balancing and SSL termination.
// - Monitor startup logs and errors to ensure the application initializes correctly.
func main() {
	// Initialize the application with all dependencies (logger, config, database, router).
	app, err := newApp()
	if err != nil {
		// Log the initialization error and exit with status code 1.
		// The logger is not yet available, so use slog directly.
		slog.Error("Failed to initialize application", "error", err)
		os.Exit(1)
	}

	// Run database migrations to create or update the users table and ensure the email unique index.
	if err := app.DB.Migrate(); err != nil {
		// Log the migration error using the app's logger and exit with status code 1.
		app.Logger.Error("Failed to migrate database", "error", err)
		os.Exit(1)
	}

	// Log a message indicating the server is starting, including the port from the configuration.
	app.Logger.Info("Starting server", "port", app.Config.Port)

	// Start the HTTP server on the configured port (e.g., ":8080").
	// The router handles all incoming requests according to defined routes and middleware.
	if err := app.Router.Start(":" + app.Config.Port); err != nil {
		// Log the server error using the app's logger and exit with status code 1.
		app.Logger.Error("Server failed", "error", err)
		os.Exit(1)
	}
}

/*
### Summary of main.go in JWT Authentication
The `main.go` file serves as the entry point for the JWT-based authentication system, providing:
- **App Struct**: Centralizes application dependencies (database, router, configuration, logger).
- **newApp Function**: Initializes all dependencies, ensuring the application is ready to run.
- **main Function**: Orchestrates startup by initializing dependencies, running migrations, and starting the HTTP server.

### Production Use Case Guidance
For developers building a JWT authentication system in Go:
1. **Initialization**:
   - Use the `App` struct to centralize dependencies, making it easier to manage and test.
   - Call `newApp` early in the startup process to ensure all components are initialized.
   - Validate all dependencies (e.g., non-nil DB, Router, Config) before proceeding.
2. **Error Handling**:
   - Log all initialization and startup errors using a structured logger (`slog`) for debugging.
   - Exit with a non-zero status code (`os.Exit(1)`) on critical failures to signal issues to the deployment system.
   - Avoid running the server if migrations fail, as the database schema is critical for operation.
3. **Database Migrations**:
   - Run migrations in `main` or a separate migration script to ensure the database schema is ready.
   - Verify database user permissions (CREATE, USAGE) before migrations to avoid runtime errors.
   - Consider using a migration tool (e.g., `golang-migrate/migrate`) for complex schema changes in production.
4. **Server Setup**:
   - Configure the HTTP server with timeouts (`ReadTimeout`, `WriteTimeout`) and graceful shutdown for robustness.
   - Use HTTPS with TLS certificates for secure communication in production.
   - Deploy behind a reverse proxy (e.g., Nginx, Traefik) for load balancing, SSL termination, and rate-limiting.
5. **Logging and Monitoring**:
   - Use `slog` for structured, machine-readable logs to facilitate monitoring and debugging.
   - Log startup events, errors, and server status for auditing and alerting.
   - Integrate with monitoring tools (e.g., Prometheus, Grafana) to track application health and performance.
6. **Testing**:
   - Test the `newApp` function in isolation by mocking dependencies (e.g., database, router).
   - Use a test-specific database or truncate tables to avoid polluting production data.
   - Verify server startup and endpoint accessibility using tools like `curl` or Postman.
*/
