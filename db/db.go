package db

// The db package provides database operations for the JWT authentication system.
// It uses GORM, a popular Object-Relational Mapping (ORM) library for Go, to interact with a PostgreSQL database.
// The package defines a DB struct to wrap the GORM database instance, a User struct to represent users,
// and functions to initialize the database, manage schema migrations, create users, and authenticate users.
// In a JWT-based system, this package handles persistent storage of user data (e.g., email, hashed password, role)
// and supports authentication by verifying credentials against stored data. For production, it ensures secure
// storage of passwords using bcrypt hashing and enforces email uniqueness to prevent duplicate accounts.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang-jwt-howto/config"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB Struct
// Syntax: type DB struct { *gorm.DB }
// Description:
// The DB struct wraps a GORM database instance to provide a clean interface for database operations.
// It embeds the *gorm.DB type, allowing direct access to GORM's methods (e.g., Create, Where, First)
// while encapsulating the database connection within the application's domain. This struct is used
// throughout the application to perform CRUD operations on the users table.
// In a JWT system, the DB struct is critical for storing and retrieving user data during signup
// (storing email, hashed password, role) and signin (verifying credentials). For production, wrapping
// GORM in a custom struct allows for easier dependency injection and mocking during testing.
// Fields:
// - *gorm.DB: The embedded GORM database instance, providing access to database operations.
// Usage in Production:
// - Initialize with New() to connect to PostgreSQL.
// - Inject into handlers (e.g., via context) to perform database operations.
// - Ensure proper connection pooling settings for scalability.
type DB struct {
	*gorm.DB
}

// User Struct
// Syntax: type User struct { gorm.Model; Name string; Email string; Password string; Role string }
// Description:
// The User struct represents a user entity in the PostgreSQL database, mapping to the "users" table.
// It embeds gorm.Model to include standard fields (ID, CreatedAt, UpdatedAt, DeletedAt) for automatic
// primary key and timestamp management. The struct defines fields for user data required in a JWT
// authentication system: name, email, hashed password, and role (e.g., "user" or "admin"). The email
// field is marked as unique to prevent duplicate accounts, and the role determines access permissions
// for protected endpoints. In a JWT system, this struct is used to store user data during signup and
// retrieve it during signin to generate JWT tokens with user-specific claims (e.g., email, role).
// Fields:
//   - gorm.Model: Embeds GORM's standard fields (ID, CreatedAt, UpdatedAt, DeletedAt) for automatic
//     table management, including soft deletes (records are marked deleted with a timestamp rather
//     than being physically removed).
//   - Name (string): The user's display name, stored as a VARCHAR(255) in the database.
//   - Email (string): The user's email address, stored as a VARCHAR(255) with a unique index to ensure
//     no duplicates. The gorm tag "unique;type:varchar(255);index:idx_email,unique" enforces this.
//   - Password (string): The hashed user password, stored as a VARCHAR(255) using bcrypt for security.
//   - Role (string): The user's role (e.g., "user" or "admin"), stored as a VARCHAR(20), used to
//     enforce role-based access control in JWT tokens.
//
// GORM Tags:
//   - json:"name": Maps the Name field to the "name" key in JSON responses.
//   - gorm:"type:varchar(255)": Specifies the database column type for Name.
//   - json:"email" gorm:"unique;type:varchar(255);index:idx_email,unique": Ensures Email is unique
//     and creates an index named idx_email.
//   - json:"password" gorm:"type:varchar(255)": Specifies the Password column type.
//   - json:"role" gorm:"type:varchar(20)": Specifies the Role column type.
//
// Usage in Production:
// - Use during signup to store user data securely (hash passwords with bcrypt).
// - Retrieve during signin to verify credentials and populate JWT claims.
// - Ensure the database enforces the unique email constraint to prevent duplicate accounts.
// - Consider adding additional fields (e.g., last_login, status) for enhanced functionality.
type User struct {
	gorm.Model
	Name     string `json:"name" gorm:"type:varchar(255)"`
	Email    string `json:"email" gorm:"unique;type:varchar(255);index:idx_email,unique"`
	Password string `json:"password" gorm:"type:varchar(255)"`
	Role     string `json:"role" gorm:"type:varchar(20)"`
}

// New Function
// Syntax: func New(databaseURL, schema string) (*DB, error)
// Description:
// The New function initializes a new PostgreSQL database connection using GORM and returns a DB struct.
// It takes a database URL (e.g., from .env) and a schema name (e.g., "public") to configure the connection.
// The function sets up connection pooling for scalability, pings the database to verify connectivity, and
// sets the schema search path if needed. In a JWT system, this function establishes the database connection
// used for all user-related operations (signup, signin, authentication). It’s called once during application
// startup to create a single DB instance shared across handlers.
// Parameters:
//   - databaseURL (string): The PostgreSQL connection string (e.g., "host=localhost port=5433 user=postgresdb1
//     dbname=userdb password=1234567890 sslmode=disable") specifying the database host, port, user, password,
//     and database name.
//   - schema (string): The database schema to use (e.g., "public"). Determines the namespace for tables.
//
// Returns:
// - *DB: A pointer to the initialized DB struct wrapping the GORM database instance.
// - error: An error if the connection fails, wrapped with context (e.g., "failed to connect to database").
// Mechanics:
//   - Uses gorm.Open with postgres.Open to establish a PostgreSQL connection.
//   - Configures connection pooling with SetMaxIdleConns (10), SetMaxOpenConns (100), and SetConnMaxLifetime
//     (1 hour) to optimize resource usage.
//   - Pings the database to ensure it’s reachable.
//   - Sets the schema search path if not "public" to isolate table operations.
//
// Usage in Production:
// - Call New during application startup (e.g., in main.go) to initialize the database.
// - Store the DB instance in the application struct and pass it to handlers via context.
// - Ensure the databaseURL is securely loaded from environment variables (e.g., via .env).
// - Adjust connection pooling settings based on expected traffic (e.g., increase MaxOpenConns for high load).
// - Handle errors gracefully, logging them and exiting the application if the database is unreachable.
func New(databaseURL, schema string) (*DB, error) {
	// Connect to PostgreSQL using GORM and the provided database URL.
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		// Wrap the error with context for better debugging.
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get the underlying SQL database instance for low-level configuration.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// Configure connection pooling to manage database connections efficiently.
	// MaxIdleConns (10) limits idle connections to prevent resource waste.
	// MaxOpenConns (100) caps total open connections to avoid overwhelming the database.
	// ConnMaxLifetime (1 hour) ensures connections are recycled to prevent stale connections.
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Ping the database to verify connectivity.
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set the schema search path if a non-default schema is specified.
	// This ensures tables are created and queried in the correct schema (e.g., not "public").
	if schema != "public" {
		if err := db.Exec("SET search_path TO ?", schema).Error; err != nil {
			return nil, fmt.Errorf("failed to set search_path to %s: %w", schema, err)
		}
	}

	// Return the DB struct wrapping the GORM instance.
	return &DB{db}, nil
}

// Migrate Function
// Syntax: func (db *DB) Migrate() error
// Description:
// The Migrate function sets up the database schema by creating or updating the "users" table
// based on the User struct definition. It checks if the database user has CREATE privileges
// on the specified schema (e.g., "public"), runs GORM's AutoMigrate to create/update the table,
// and ensures a unique index on the email field to enforce uniqueness at the database level.
// In a JWT system, this function is critical for initializing the database schema to store
// user data securely. It’s called during application startup to ensure the table exists
// before any user operations (signup, signin).
// Parameters:
// - None (operates on the receiver *DB).
// Returns:
// - error: An error if privilege checks, migration, or index creation fails, wrapped with context.
// Mechanics:
// - Checks schema privileges using has_schema_privilege to ensure the user can create tables.
// - Uses AutoMigrate to create or update the users table based on the User struct.
// - Creates a unique index on the email field (excluding soft-deleted records) to enforce uniqueness.
// Usage in Production:
// - Call Migrate during application startup after initializing the DB instance.
// - Ensure the database user has CREATE and USAGE privileges on the schema.
// - Verify the unique index on email to prevent duplicate accounts at the database level.
// - Handle errors by logging and notifying administrators, as schema issues can block user operations.
// - Consider running migrations in a separate script for large-scale deployments to avoid runtime errors.
func (db *DB) Migrate() error {
	// Check if the database user has CREATE privilege on the schema.
	// This ensures the user can create tables and indexes in the specified schema (e.g., "public").
	var result bool
	err := db.Raw("SELECT has_schema_privilege(current_user, ?, 'CREATE')", "public").Scan(&result).Error
	if err != nil {
		return fmt.Errorf("failed to check schema privileges: %w", err)
	}
	if !result {
		// If the user lacks privileges, provide a helpful error message with the SQL command to fix it.
		user := getDBUser(os.Getenv("DATABASE_URL"))
		return fmt.Errorf("user lacks CREATE privilege on schema public. Grant permissions using: GRANT CREATE, USAGE ON SCHEMA public TO %s", user)
	}

	// Run AutoMigrate to create or update the users table based on the User struct.
	// This creates columns for ID, CreatedAt, UpdatedAt, DeletedAt (from gorm.Model),
	// and Name, Email, Password, Role with their specified types and constraints.
	if err := db.AutoMigrate(&User{}); err != nil {
		return fmt.Errorf("failed to migrate user table: %w", err)
	}

	// Create a unique index on the email column (excluding soft-deleted records) to enforce
	// uniqueness at the database level. The "IF NOT EXISTS" ensures idempotency, preventing
	// errors if the index already exists. This is critical for preventing duplicate email
	// addresses in a JWT system, ensuring each user has a unique identifier.
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_email ON users (email) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create unique index on email: %w", err)
	}

	return nil
}

// CreateUser Function
// Syntax: func CreateUser(ctx context.Context, user User) error
// Description:
// The CreateUser function creates a new user in the database by storing their name, email,
// hashed password, and role. It uses a transaction to ensure atomicity, checks for duplicate
// emails to prevent conflicts, and hashes the password using bcrypt for security. In a JWT
// system, this function is called during the signup process to persist user data before issuing
// a JWT token. It retrieves the database instance from the context to ensure thread-safe access
// and avoid global variables.
// Parameters:
// - ctx (context.Context): The Go context containing the DB instance, passed via config.DBContextKey.
// - user (User): The User struct containing the name, email, plaintext password, and role to store.
// Returns:
//   - error: An error if the database is missing from context, transaction fails, email is duplicate,
//     password hashing fails, or user creation fails, wrapped with context.
//
// Mechanics:
// - Retrieves the DB instance from the context using config.DBContextKey.
// - Starts a transaction to ensure atomicity (either all operations succeed or none do).
// - Checks for an existing user with the same email to enforce uniqueness.
// - Hashes the password using bcrypt with the default cost factor for security.
// - Creates the user record in the database and commits the transaction.
// Usage in Production:
//   - Call during the signup endpoint (/signup) to create new users.
//   - Ensure the context includes the DB instance (e.g., via middleware or handler setup).
//   - Use a strong bcrypt cost factor (default is sufficient for most cases) but adjust based on
//     performance needs.
//   - Log errors for debugging and notify administrators of persistent issues (e.g., database failures).
//   - Consider adding validation for email format and password strength before calling this function.
func CreateUser(ctx context.Context, user User) error {
	// Retrieve the DB instance from the context to ensure thread-safe database access.
	// Using context avoids global variables and supports dependency injection.
	db, ok := ctx.Value(config.DBContextKey).(*DB)
	if !ok {
		return fmt.Errorf("database not found in context")
	}

	// Start a transaction to ensure atomicity of the user creation process.
	// If any step fails, the transaction is rolled back to maintain database consistency.
	tx := db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to start transaction: %w", tx.Error)
	}

	// Check if a user with the same email already exists to prevent duplicates.
	// The query excludes soft-deleted records (deleted_at IS NULL) due to GORM's soft delete feature.
	var existingUser User
	if err := tx.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		// If a user is found, rollback the transaction and return an error.
		tx.Rollback()
		return fmt.Errorf("email already exists")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		// If the query fails for reasons other than "record not found," rollback and return the error.
		tx.Rollback()
		return fmt.Errorf("failed to check existing user: %w", err)
	}

	// Hash the user's plaintext password using bcrypt for secure storage.
	// bcrypt generates a salted hash, making it resistant to rainbow table attacks.
	// The default cost factor balances security and performance but can be adjusted for stronger hashing.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to hash password: %w", err)
	}
	user.Password = string(hashedPassword)

	// Create the user record in the database using the transaction.
	// This inserts the user’s name, email, hashed password, and role into the users table.
	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Commit the transaction to persist the user record.
	// If this fails, the error is returned, and no changes are applied.
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// AuthenticateUser Function
// Syntax: func AuthenticateUser(ctx context.Context, email, password string) (User, error)
// Description:
// The AuthenticateUser function verifies a user’s credentials by checking their email and password
// against the database. It retrieves the user by email, compares the provided password with the stored
// hashed password using bcrypt, and returns the user if authentication succeeds. In a JWT system, this
// function is called during the signin process to verify credentials before generating a JWT token with
// the user’s email and role as claims. It uses the context to access the DB instance for thread safety.
// Parameters:
// - ctx (context.Context): The Go context containing the DB instance, passed via config.DBContextKey.
// - email (string): The user’s email address to look up in the database.
// - password (string): The plaintext password to verify against the stored hashed password.
// Returns:
//   - User: The authenticated user’s data (name, email, role, etc.) if credentials are valid.
//   - error: An error if the database is missing from context, the user is not found, or the password is
//     invalid, wrapped with context.
//
// Mechanics:
// - Retrieves the DB instance from the context.
// - Queries the users table for a user with the given email (excluding soft-deleted records).
// - Uses bcrypt to compare the provided plaintext password with the stored hashed password.
// - Returns the user struct if authentication succeeds, or an error if it fails.
// Usage in Production:
// - Call during the signin endpoint (/signin) to verify user credentials.
// - Use the returned User struct to populate JWT claims (e.g., email, role).
// - Ensure the context includes the DB instance.
// - Log failed authentication attempts for security monitoring (e.g., brute-force detection).
// - Consider rate-limiting signin attempts to prevent abuse in production systems.
func AuthenticateUser(ctx context.Context, email, password string) (User, error) {
	// Retrieve the DB instance from the context for thread-safe access.
	db, ok := ctx.Value(config.DBContextKey).(*DB)
	if !ok {
		return User{}, fmt.Errorf("database not found in context")
	}

	// Query the users table for a user with the given email, excluding soft-deleted records.
	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		return User{}, fmt.Errorf("failed to find user: %w", err)
	}

	// Compare the provided plaintext password with the stored hashed password using bcrypt.
	// bcrypt handles salt verification internally, ensuring secure password comparison.
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return User{}, fmt.Errorf("invalid password: %w", err)
	}

	// Return the user struct if authentication succeeds.
	return user, nil
}

// getDBUser Function
// Syntax: func getDBUser(databaseURL string) string
// Description:
// The getDBUser function extracts the database user’s username from the DATABASE_URL connection string
// for use in error messages. It parses the connection string to find the "user=" parameter and returns
// the username. This function is used in the Migrate function to provide helpful error messages when
// the database user lacks CREATE privileges, guiding administrators on how to grant permissions.
// In a JWT system, this function is a utility to improve error handling and debugging, ensuring
// actionable feedback for database configuration issues.
// Parameters:
// - databaseURL (string): The PostgreSQL connection string containing the username (e.g., "user=postgresdb1").
// Returns:
// - string: The extracted username, or "your_database_user" if parsing fails.
// Mechanics:
// - Splits the databaseURL into parts based on spaces.
// - Searches for the "user=" prefix and extracts the username.
// - Returns a default value if the username is not found.
// Usage in Production:
// - Use in error messages to provide specific instructions for granting database permissions.
// - Ensure the DATABASE_URL is correctly formatted to avoid parsing errors.
// - Consider logging the full DATABASE_URL (with password masked) for debugging connection issues.
func getDBUser(databaseURL string) string {
	// Split the connection string into parts to parse the user parameter.
	parts := strings.Split(databaseURL, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "user=") {
			// Extract and return the username after "user=".
			return strings.TrimPrefix(part, "user=")
		}
	}
	// Return a default value if the username is not found.
	return "your_database_user"
}

/*
### Summary of db/db.go in JWT Authentication
This 'db' package is the backbone of user data management in this JWT-based authentication system. It uses PostgreSQL via GORM to store and retrieve user data securely, with the following key roles:
- **DB Struct**: Encapsulates the GORM database instance for consistent database access.
- **User Struct**: Defines the user entity with fields critical for JWT authentication (email, role) and secure password storage.
- **New Function**: Initializes the database connection with proper pooling and schema settings.
- **Migrate Function**: Sets up the database schema with a unique email constraint.
- **CreateUser Function**: Handles user signup by storing hashed passwords and ensuring email uniqueness.
- **AuthenticateUser Function**: Verifies credentials for signin, enabling JWT token generation.
- **getDBUser Function**: Enhances error messages for better debugging.

### Production Use Case Guidance
For developers building a JWT authentication system in Go:
1. **Database Choice**: PostgreSQL is a robust choice due to its support for unique constraints and transactions. Use GORM for ORM simplicity, but understand its conventions (e.g., soft deletes).
2. **Security**:
   - Always hash passwords with bcrypt (or similar) to protect user credentials.
   - Enforce email uniqueness at both application (CreateUser) and database (unique index) levels.
   - Use transactions to ensure atomicity in user creation to avoid partial writes.
3. **Scalability**:
   - Configure connection pooling (MaxOpenConns, MaxIdleConns) based on expected traffic.
   - Monitor database performance and adjust ConnMaxLifetime for long-running applications.
4. **Error Handling**:
   - Wrap errors with context (e.g., fmt.Errorf) for clear debugging.
   - Log database errors and notify administrators of persistent issues.
5. **Testing**:
   - Use a separate test database or truncate tables to avoid polluting production data.
   - Mock the DB struct for unit tests to isolate database logic.
6. **Schema Management**:
   - Run migrations during deployment, not runtime, for large-scale systems.
   - Verify user permissions (CREATE, USAGE) before migrations to avoid runtime failures.
*/
