# PostgreSQL Setup and Management Guide for JWT Authentication System

This guide provides detailed instructions for setting up and managing PostgreSQL databases to support the JWT-based authentication system implemented in the provided Go program. It covers creating databases, users, setting passwords, and granting minimal privileges (`SELECT`, `INSERT`, `UPDATE`, `DELETE` on the `users` table) for the `userdb` database, `postgresdb1` user, and password `1234567890`. Instructions are provided for two setups: **Debian-based Linux** with a local PostgreSQL instance and **macOS** with PostgreSQL running in a Docker container. The guide also supports managing multiple database instances for development and testing environments and includes troubleshooting steps for privilege-related issues.

**Choose Your Setup**:
- [Debian-based Linux with Local PostgreSQL](#debian-based-linux-with-local-postgresql)
- [macOS with PostgreSQL in Docker](#macos-with-postgresql-in-docker)

For installation instructions, refer to the official PostgreSQL documentation: [Linux](https://www.postgresql.org/download/linux/) or [macOS](https://www.postgresql.org/download/macosx/). For Docker on macOS, see [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/).

---

## Debian-based Linux with Local PostgreSQL

This section guides users running a local PostgreSQL instance on a Debian-based Linux system (e.g., Ubuntu) to configure the database for the JWT authentication system.

### 1. Verify PostgreSQL Installation

Ensure PostgreSQL is installed and running on your Debian-based system.

#### Steps:
- **Check PostgreSQL Version**: Confirm the installed version for compatibility.
  ```bash
  psql --version
  ```
  Expected output (example): `psql (PostgreSQL) 16.4`.

- **Check Service Status**: Verify the PostgreSQL service is running.
  ```bash
  sudo systemctl status postgresql
  ```
  If not running, start and enable it:
  ```bash
  sudo systemctl start postgresql
  sudo systemctl enable postgresql
  ```

- **Installation Note**: If PostgreSQL is not installed, refer to the [PostgreSQL Linux Installation Guide](https://www.postgresql.org/download/linux/). On Debian/Ubuntu:
  ```bash
  sudo apt update
  sudo apt install postgresql postgresql-contrib
  ```

#### Production Notes:
- Ensure the PostgreSQL version supports GORM (9.6+).
- Monitor service uptime with `systemctl` or tools like Prometheus.
- Set up automated backups using `pg_dump` or a managed service.

### 2. Configure PostgreSQL for Multiple Instances

To support multiple environments (e.g., development, testing), create separate PostgreSQL clusters with unique ports and data directories.

#### Step 2.1: Create a New PostgreSQL Cluster
Use `pg_createcluster` to create a cluster named `myapp` on port 5433 (to match the Go program’s expectation):
```bash
sudo pg_createcluster 16 myapp --port=5433
```
- `16`: Replace with your PostgreSQL version (e.g., 14, 15, 16). Check with `psql --version`.
- `myapp`: Cluster name (e.g., `jwtapp`).
- `--port=5433`: Avoids conflicts with the default cluster (port 5432).

Start the cluster:
```bash
sudo pg_ctlcluster 16 myapp start
```

#### Step 2.2: Create Additional Clusters (Optional)
For additional environments:
```bash
sudo pg_createcluster 16 myapp2 --port=5434
sudo pg_ctlcluster 16 myapp2 start
```

Each cluster has its own:
- **Data Directory**: e.g., `/var/lib/postgresql/16/myapp`
- **Configuration Files**: e.g., `/etc/postgresql/16/myapp`
- **Log File**: e.g., `/var/log/postgresql/postgresql-16-myapp.log`

#### Step 2.3: Verify Clusters
List clusters:
```bash
sudo pg_lsclusters
```

Example output:
```
Ver  Cluster  Port  Status  Owner    Data directory               Log file
16   main     5432  online  postgres /var/lib/postgresql/16/main  /var/log/postgresql/postgresql-16-main.log
16   myapp    5433  online  postgres /var/lib/postgresql/16/myapp /var/log/postgresql/postgresql-16-myapp.log
```

#### Production Notes:
- Use separate clusters for development, testing, and production.
- Assign unique ports to avoid conflicts.
- Monitor disk usage for data directories and logs.
- Consider managed services (e.g., AWS RDS) for production.

### 3. Configure the Database

The Go program expects `userdb` on port 5433 with user `postgresdb1` and password `1234567890`.

#### Step 3.1: Access the PostgreSQL Cluster
Log in to the `myapp` cluster:
```bash
sudo -u postgres psql -p 5433
```

#### Step 3.2: Create the Database User
Create `postgresdb1`:
```sql
CREATE USER postgresdb1 WITH PASSWORD '1234567890';
```

#### Step 3.3: Create the Database
Create `userdb`:
```sql
CREATE DATABASE userdb;
```

#### Step 3.4: Grant Minimal Privileges
The Go program uses GORM’s `AutoMigrate` to create the `users` table in the `public` schema and performs `INSERT`, `UPDATE`, `DELETE`, `SELECT`. Grant only necessary privileges.

Connect to `userdb`:
```bash
sudo -u postgres psql -p 5433 -d userdb
```

Grant schema privileges:
```sql
GRANT USAGE, CREATE ON SCHEMA public TO postgresdb1;
```

After `AutoMigrate` creates the `users` table, grant table privileges:
```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO postgresdb1;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO postgresdb1;
```

Optionally, create the `users` table manually:
```sql
CREATE TABLE public.users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO postgresdb1;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO postgresdb1;
```

Exit `psql`:
```sql
\q
```

#### Step 3.5: Test Database Connection
Test the connection:
```bash
psql -h localhost -p 5433 -U postgresdb1 -d userdb
```
Enter password `1234567890`. Test operations:
```sql
SELECT * FROM public.users;
INSERT INTO public.users (name, email, password, role) VALUES ('Test User', 'test@example.com', 'hashedpassword', 'user');
```

#### Production Notes:
- Use strong passwords (e.g., `openssl rand -base64 12`).
- Grant `CONNECT` on the database:
  ```sql
  REVOKE ALL ON DATABASE userdb FROM postgresdb1;
  GRANT CONNECT ON DATABASE userdb TO postgresdb1;
  ```
- Use `sslmode=require` in production.
- Test privileges before running the program.

### 4. Configure PostgreSQL Authentication

The Go program uses:
```
postgres://postgresdb1:1234567890@localhost:5433/userdb?sslmode=disable
```

#### Step 4.1: Edit pg_hba.conf
Edit `/etc/postgresql/16/myapp/pg_hba.conf`:
```bash
sudo nano /etc/postgresql/16/myapp/pg_hba.conf
```

Add:
```
host    userdb          postgresdb1     127.0.0.1/32            scram-sha-256
```

#### Step 4.2: Restart the Cluster
```bash
sudo pg_ctlcluster 16 myapp restart
```

#### Step 4.3: Verify Authentication
```bash
psql -h localhost -p 5433 -U postgresdb1 -d userdb
```

#### Production Notes:
- Use `scram-sha-256` for secure authentication.
- Restrict to specific IPs/users.
- Enable `hostssl` for production.
- Audit `pg_hba.conf` regularly.

---

## macOS with PostgreSQL in Docker

This section guides users running PostgreSQL in a Docker container on macOS, using Docker Desktop to manage the database for the JWT authentication system.

### 1. Verify Docker Installation

Ensure Docker Desktop is installed and running on macOS.

#### Steps:
- **Check Docker Version**:
  ```bash
  docker --version
  ```
  Expected output: `Docker version 27.3.1, build ce122303`.
  If not installed, download from [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/).

- **Run PostgreSQL Container**: Start a container for `myapp`:
  ```bash
  docker run --name myapp-postgres -p 5433:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=adminpassword -d postgres:16
  ```
  - `-p 5433:5432`: Maps container port 5432 to host port 5433.
  - `-e POSTGRES_USER=postgres`: Default superuser.
  - `-e POSTGRES_PASSWORD=adminpassword`: Temporary password.
  - `postgres:16`: PostgreSQL 16 image.

- **Verify Container Status**:
  ```bash
  docker ps
  ```
  Expected output:
  ```
  CONTAINER ID   IMAGE         COMMAND                  PORTS                    NAMES
  abc123def456   postgres:16   "docker-entrypoint.s…"   0.0.0.0:5433->5432/tcp   myapp-postgres
  ```

- **Access psql**:
  ```bash
  docker exec -it myapp-postgres psql -U postgres
  ```

#### Production Notes:
- Use a specific version tag (e.g., `postgres:16`).
- Persist data with a volume:
  ```bash
  docker run --name myapp-postgres -p 5433:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=adminpassword -v pgdata:/var/lib/postgresql/data -d postgres:16
  ```
- Monitor container health with Docker Desktop or `docker stats`.

### 2. Configure PostgreSQL for Multiple Instances

Use multiple containers for different environments.

#### Step 2.1: Create a PostgreSQL Container
The `myapp-postgres` container is created (Step 1).

#### Step 2.2: Create Additional Containers (Optional)
Run another container:
```bash
docker run --name myapp2-postgres -p 5434:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=adminpassword -d postgres:16
```

#### Step 2.3: Verify Containers
```bash
docker ps
```

**Docker Compose Example**:
```yaml
version: '3.8'
services:
  myapp-postgres:
    image: postgres:16
    container_name: myapp-postgres
    ports:
      - "5433:5432"
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: adminpassword
    volumes:
      - pgdata-myapp:/var/lib/postgresql/data
  myapp2-postgres:
    image: postgres:16
    container_name: myapp2-postgres
    ports:
      - "5434:5432"
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: adminpassword
    volumes:
      - pgdata-myapp2:/var/lib/postgresql/data
volumes:
  pgdata-myapp:
  pgdata-myapp2:
```
Run:
```bash
docker-compose up -d
```

#### Production Notes:
- Use unique container names and ports.
- Persist data with named volumes.
- Monitor logs: `docker logs myapp-postgres`.

### 3. Configure the Database

#### Step 3.1: Access the PostgreSQL Container
```bash
docker exec -it myapp-postgres psql -U postgres
```

#### Step 3.2: Create the Database User
```sql
CREATE USER postgresdb1 WITH PASSWORD '1234567890';
```

#### Step 3.3: Create the Database
```sql
CREATE DATABASE userdb;
```

#### Step 3.4: Grant Minimal Privileges
Connect to `userdb`:
```bash
docker exec -it myapp-postgres psql -U postgres -d userdb
```

Grant schema privileges:
```sql
GRANT USAGE, CREATE ON SCHEMA public TO postgresdb1;
```

Grant table privileges (after `AutoMigrate`):
```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO postgresdb1;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO postgresdb1;
```

Or create `users` manually:
```sql
CREATE TABLE public.users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO postgresdb1;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO postgresdb1;
```

Exit:
```sql
\q
```

#### Step 3.5: Test Database Connection
Test inside the container:
```bash
docker exec -it myapp-postgres psql -h localhost -p 5432 -U postgresdb1 -d userdb
```

Test from macOS:
```bash
psql -h localhost -p 5433 -U postgresdb1 -d userdb
```

#### Production Notes:
- Grant `CONNECT`:
  ```sql
  REVOKE ALL ON DATABASE userdb FROM postgresdb1;
  GRANT CONNECT ON DATABASE userdb TO postgresdb1;
  ```
- Use strong passwords.
- Enable SSL in production.

### 4. Configure PostgreSQL Authentication

#### Step 4.1: Edit pg_hba.conf
Copy `pg_hba.conf`:
```bash
docker cp myapp-postgres:/var/lib/postgresql/data/pg_hba.conf ./pg_hba.conf
```

Edit:
```bash
nano ./pg_hba.conf
```

Add:
```
host    userdb          postgresdb1     0.0.0.0/0            scram-sha-256
```

Copy back:
```bash
docker cp ./pg_hba.conf myapp-postgres:/var/lib/postgresql/data/pg_hba.conf
```

#### Step 4.2: Restart the Container
```bash
docker restart myapp-postgres
```

#### Step 4.3: Verify Authentication
```bash
psql -h localhost -p 5433 -U postgresdb1 -d userdb
```

**Docker Compose Alternative**:
```yaml
volumes:
  - ./pg_hba.conf:/var/lib/postgresql/data/pg_hba.conf
```

#### Production Notes:
- Use `scram-sha-256`.
- Restrict to Docker network IPs (e.g., `172.17.0.0/16`).
- Enable `hostssl` with certificates.

---

## Managing Multiple Databases for Development

### Debian-based Linux
Create a new cluster:
```bash
sudo pg_createcluster 16 myapp2 --port=5434
sudo pg_ctlcluster 16 myapp2 start
```

Create user and database:
```bash
sudo -u postgres psql -p 5434
```
```sql
CREATE USER newuser WITH PASSWORD 'newpassword';
CREATE DATABASE newdb;
GRANT USAGE, CREATE ON SCHEMA public TO newuser;
\connect newdb
CREATE TABLE public.users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO newuser;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO newuser;
\q
```

Update Go program:
```go
databaseurl := "host=localhost port=5434 user=newuser dbname=newdb password=newpassword sslmode=disable"
```

### macOS with Docker
Run a new container:
```bash
docker run --name myapp2-postgres -p 5434:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=adminpassword -d postgres:16
```

Create user and database:
```bash
docker exec -it myapp2-postgres psql -U postgres
```
```sql
CREATE USER newuser WITH PASSWORD 'newpassword';
CREATE DATABASE newdb;
GRANT USAGE, CREATE ON SCHEMA public TO newuser;
\connect newdb
CREATE TABLE public.users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO newuser;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO newuser;
\q
```

Update Go program with environment variables:
```bash
export DB_PORT=5434
export DB_USER=newuser
export DB_NAME=newdb
export DB_PASSWORD=newpassword
```

#### Production Notes:
- Use Docker Compose for multi-container setups.
- Persist data with volumes.
- Automate setups with scripts or Terraform.

---

## Troubleshooting

### Debian-based Linux
- **Connection Errors**:
  - Check cluster: `sudo pg_ctlcluster 16 myapp status`.
  - Verify port: 5433.
- **Authentication Errors**:
  - Check `pg_hba.conf`.
- **Privilege Errors**:
  - **Symptom**: `ERROR: permission denied for table users` or `ERROR: permission denied for schema public`.
  - **Diagnosis**:
    ```bash
    sudo -u postgres psql -p 5433 -d userdb
    ```
    ```sql
    \dp public.users
    \dn+ public
    ```
    Expected: `postgresdb1=crud/postgres` for `users`, `postgresdb1=UC/postgres` for `public`.
  - **Solution**:
    ```sql
    GRANT USAGE, CREATE ON SCHEMA public TO postgresdb1;
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO postgresdb1;
    GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO postgresdb1;
    ```

### macOS with Docker
- **Connection Errors**:
  - Check container: `docker ps`.
  - Verify host port: 5433.
- **Authentication Errors**:
  - Check logs: `docker logs myapp-postgres`.
- **Privilege Errors**:
  - **Diagnosis**:
    ```bash
    docker exec -it myapp-postgres psql -U postgres -d userdb
    ```
    ```sql
    \dp public.users
    \dn+ public
    ```
  - **Solution**:
    ```sql
    GRANT USAGE, CREATE ON SCHEMA public TO postgresdb1;
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO postgresdb1;
    GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO postgresdb1;
    ```

#### Production Notes:
- Log errors to a monitoring system.
- Test privileges in staging.

---

## Security Best Practices

### Minimal Privilege Configuration
- Grant only:
  ```sql
  REVOKE ALL ON DATABASE userdb FROM postgresdb1;
  GRANT CONNECT ON DATABASE userdb TO postgresdb1;
  GRANT USAGE, CREATE ON SCHEMA public TO postgresdb1;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO postgresdb1;
  GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO postgresdb1;
  ```
- Audit privileges:
  ```sql
  \dp public.*
  \dn+ public
  ```

### Other Security Practices
- Use strong passwords.
- Store credentials in environment variables:
  ```go
  databaseurl := fmt.Sprintf("host=localhost port=%s user=%s dbname=%s password=%s sslmode=require",
      os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_NAME"), os.Getenv("DB_PASSWORD"))
  ```
- Enable SSL in production.
- Restrict `pg_hba.conf` access.
- Schedule backups with `pg_dump` (Linux) or `docker exec ... pg_dump` (Docker).

---

## Summary

This guide covers:
- Setting up `userdb` and `postgresdb1` with minimal privileges for Debian-based Linux and macOS with Docker.
- Managing multiple instances (clusters or containers).
- Troubleshooting privilege issues.
- Applying security best practices.

Test the connection:
```bash
psql -h localhost -p 5433 -U postgresdb1 -d userdb
```

Refer to [PostgreSQL Documentation](https://www.postgresql.org/docs/) for further details.