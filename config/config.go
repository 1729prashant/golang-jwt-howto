package config

// The config package manages the application's configuration settings, which are critical for a JWT-based
// authentication system. It loads environment variables from a .env file to configure the database connection,
// JWT secret key, server port, CORS settings, and database schema. The package defines a Config struct to hold
// these settings, a custom contextKey type to prevent context key collisions, and constants for context keys used
// in request handling. The Load function populates the Config struct from environment variables, ensuring secure
// and flexible configuration management. In a JWT system, this package provides the necessary settings for
// database connectivity (used by db/db.go), JWT token generation (used by auth/auth.go), server setup (used by
// main.go), and CORS handling (used by api/handlers.go). For production, it ensures sensitive data like the JWT
// secret and database credentials are securely loaded from environment variables rather than hard-coded.

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config Struct
// Syntax: type Config struct { DatabaseURL string; JWTSecret string; Port string; CORSAllowedOrigin string; DBSchema string }
// Description:
// The Config struct holds the application's configuration settings loaded from environment variables. These
// settings are essential for running the JWT authentication system, including connecting to the PostgreSQL
// database, generating and verifying JWT tokens, running the HTTP server, enabling CORS for cross-origin
// requests, and specifying the database schema. The struct centralizes configuration to make it easily
// accessible across the application (e.g., in main.go, db.go, auth.go, and handlers.go). In a JWT system,
// the Config struct provides the JWTSecret for signing tokens, DatabaseURL for user storage, Port for the
// server, CORSAllowedOrigin for client access, and DBSchema for database operations.
// Fields:
//   - DatabaseURL (string): The PostgreSQL connection string (e.g., "host=localhost port=5433 user=postgresdb1
//     dbname=userdb password=1234567890 sslmode=disable") used to connect to the database.
//   - JWTSecret (string): The secret key used to sign and verify JWT tokens, ensuring their integrity and
//     authenticity.
//   - Port (string): The port on which the HTTP server listens (e.g., "8080").
//   - CORSAllowedOrigin (string): The allowed origin for CORS requests (e.g., "http://localhost:3000"),
//     controlling which clients can access the API.
//   - DBSchema (string): The database schema (e.g., "public") used for table operations, allowing isolation
//     of tables in multi-tenant applications.
//
// Usage in Production:
// - Initialize with Load() during application startup and pass to other components (e.g., database, router).
// - Store sensitive data (DatabaseURL, JWTSecret) in environment variables or a secure vault, never in code.
// - Validate all fields to ensure non-empty values for critical settings (e.g., JWTSecret, DatabaseURL).
// - Use a strong, random JWTSecret (at least 32 bytes) to prevent token forging.
// - Adjust CORSAllowedOrigin to match production client domains (e.g., "https://yourapp.com").
// - Set DBSchema to isolate data in multi-tenant systems or keep as "public" for simplicity.
type Config struct {
	DatabaseURL       string
	JWTSecret         string
	Port              string
	CORSAllowedOrigin string
	DBSchema          string // Schema for database operations
}

// contextKey Type
// Syntax: type contextKey string
// Description:
// The contextKey type is a custom string type used to define keys for storing values in the Go context
// (context.Context). It prevents key collisions by ensuring unique, type-safe keys for values like the
// database instance or user role during request handling. In a JWT system, context keys are used to pass
// the database instance (DB) and authenticated user’s role between middleware and handlers, enabling
// secure and efficient request processing. This type is critical for avoiding hard-coded string keys,
// which can lead to conflicts in large applications.
// Usage in Production:
// - Define context keys as constants (e.g., RoleContextKey, DBContextKey) to ensure consistency.
// - Use contextKey for all context value keys to prevent collisions with other packages.
// - Ensure context values are set in middleware (e.g., database instance, JWT claims) and accessed in handlers.
// - Avoid storing sensitive data in context unless necessary, and never store unencrypted passwords.
type contextKey string

// Context Key Constants
// Syntax: const ( RoleContextKey contextKey = "role"; DBContextKey contextKey = "db" )
// Description:
// These constants define specific context keys for storing values in the request context. RoleContextKey
// stores the authenticated user’s role (e.g., "user" or "admin") extracted from the JWT token, used for
// role-based access control. DBContextKey stores the database instance (db.DB) to provide handlers with
// access to the database without global variables. In a JWT system, these keys enable middleware to pass
// critical data (e.g., user role for authorization, database for queries) to handlers securely. They are
// defined as constants to ensure consistency and avoid typos in context key usage.
// Constants:
// - RoleContextKey (contextKey): Stores the user’s role (e.g., "user" or "admin") from the JWT token.
// - DBContextKey (contextKey): Stores the db.DB instance for database operations in handlers.
// Usage in Production:
//   - Use RoleContextKey in middleware to store the JWT’s role claim and enforce access control (e.g., only
//     "admin" can access /admin).
//   - Use DBContextKey to pass the database instance to handlers, enabling thread-safe database access.
//   - Ensure middleware sets these context values before handlers are called.
//   - Validate context values in handlers to avoid nil pointer dereferences (e.g., check if DB is present).
const (
	RoleContextKey contextKey = "role"
	DBContextKey   contextKey = "db"
)

// Load Function
// Syntax: func Load() (*Config, error)
// Description:
// The Load function reads environment variables from a .env file (or the system environment) and populates
// a Config struct with the application’s configuration settings. It uses the godotenv package to load the
// .env file, then extracts values for DatabaseURL, JWTSecret, Port, CORSAllowedOrigin, and DBSchema. If
// the DBSchema is not specified, it defaults to "public". In a JWT system, this function is called during
// application startup to initialize configuration for database connections, JWT token signing, server setup,
// and CORS handling. It ensures sensitive data is loaded securely from environment variables rather than
// hard-coded in the source code.
// Parameters:
// - None
// Returns:
// - *Config: A pointer to the populated Config struct containing all configuration settings.
// - error: An error if loading the .env file fails, wrapped with context.
// Mechanics:
// - Loads the .env file using godotenv.Load() to populate environment variables.
// - Creates a Config struct and assigns values from os.Getenv() for each required variable.
// - Sets a default DBSchema of "public" if not specified.
// - Returns the Config struct and nil error on success, or an error if .env loading fails.
// Usage in Production:
//   - Call Load during application startup (e.g., in main.go) to initialize configuration.
//   - Store the .env file outside the repository (e.g., in a secure location) and load it in production
//     using environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).
//   - Validate all fields in the Config struct to ensure non-empty values for critical settings
//     (e.g., JWTSecret, DatabaseURL) to prevent runtime errors.
//   - Use a strong, random JWTSecret (at least 32 bytes) to secure JWT tokens.
//   - Adjust CORSAllowedOrigin to match production client domains (e.g., "https://yourapp.com").
//   - Log errors from godotenv.Load() and notify administrators if configuration fails to load.
func Load() (*Config, error) {
	// Load environment variables from the .env file using godotenv.
	// This allows configuration to be stored outside the codebase, improving security.
	if err := godotenv.Load(); err != nil {
		// Wrap the error with context for better debugging.
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	// Create a Config struct and populate it with environment variable values.
	config := &Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		Port:              os.Getenv("PORT"),
		CORSAllowedOrigin: os.Getenv("CORS_ALLOWED_ORIGIN"),
		DBSchema:          os.Getenv("DB_SCHEMA"),
	}

	// Set a default schema of "public" if DBSchema is not specified.
	// This ensures the application works with the default PostgreSQL schema if none is provided.
	if config.DBSchema == "" {
		config.DBSchema = "public"
	}

	// Return the populated Config struct and nil error on success.
	return config, nil
}

/*
### Summary of config/config.go in JWT Authentication
The `config` package is responsible for managing the application's configuration, which is critical for a JWT-based authentication system. It provides:
- **Config Struct**: Centralizes configuration settings for database connectivity, JWT signing, server setup, CORS, and schema management.
- **contextKey Type**: Ensures type-safe context keys to avoid collisions in request handling.
- **Context Key Constants**: Defines keys for storing user roles and database instances in the request context, enabling secure and efficient JWT-based authorization.
- **Load Function**: Loads configuration from environment variables, ensuring sensitive data is securely managed.

### Production Use Case Guidance
For developers building a JWT authentication system in Go:
1. **Configuration Management**:
   - Store sensitive data (e.g., `DatabaseURL`, `JWTSecret`) in environment variables or a secrets manager, never in source code.
   - Use a `.env` file for development and a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault) for production.
   - Validate all configuration fields to ensure non-empty values for critical settings (e.g., add checks for `JWTSecret` and `DatabaseURL`).
2. **Security**:
   - Use a strong, random `JWTSecret` (at least 32 bytes) to prevent token forging.
   - Restrict `CORSAllowedOrigin` to trusted client domains in production (e.g., `https://yourapp.com`).
   - Mask sensitive data (e.g., passwords in `DatabaseURL`) in logs to prevent accidental exposure.
3. **Context Usage**:
   - Use `contextKey` and constants like `RoleContextKey` and `DBContextKey` for all context operations to ensure type safety.
   - Set context values in middleware (e.g., JWT role, database instance) and validate them in handlers to avoid nil pointer issues.
4. **Scalability**:
   - Ensure the `Port` is configurable to avoid conflicts in multi-service deployments.
   - Use `DBSchema` to isolate data in multi-tenant applications, setting it to a unique schema per tenant if needed.
5. **Error Handling**:
   - Log configuration loading errors and notify administrators if the `.env` file or environment variables are missing.
   - Implement fallback defaults for non-critical settings (e.g., `DBSchema`) but fail fast for critical ones (e.g., `JWTSecret`).
6. **Testing**:
   - Mock the `Config` struct in unit tests to avoid loading `.env` files in test environments.
   - Use a separate `.env.test` file for testing to isolate test configurations.
*/
