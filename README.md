# AuthProvider Project

## Project Overview

This project provides an authentication and authorization solution using OpenIddict and .NET. It includes an auth server, helper applications (resource server and the client) and a migrator tool to assist with schema evolution of the auth server's database.

## Project Structure

- `AuthProvider/`: Main solution directory
  - `AuthProvider.Client/`: Client application
  - `AuthProvider.Migrator/`: Database migration tool
  - `AuthProvider.ResourceServer/`: API resource server
  - `AuthProvider.sln`: The overall solution file
  - `Dockerfile` variants: For building Docker images of each component
- `Docs/`: Additional documentation and diagrams
  - `diagrams/`: System architecture diagrams
  - `proto/`: Figma prototype of the auth server

## Technology Stack

- **Database**: SQL Server Express 2025 LocalDB for local deployment, SQL Server 2025 image for Docker
- **Framework**: .NET 10 (ASP.NET Core MVC and Web API)
- **Authentication & Authorization**: OpenIddict for OAuth2/OpenID Connect
- **User Management**: ASP.NET Core Identity
- **ORM**: Entity Framework Core
- **Containerization**: Docker for isolated deployments (currently local)

## Local Deployment Steps

1. **Make sure that SQL Server Express LocalDB v17** is installed on your machine.
2. **Configure the database**:
   - Ensure SQL Server is running and accessible.
   - Run the migrator console application to make sure the database exists and all the migrations are applied.
3. **Build and run the application**:

   ```bash
   cd AuthProvider
   dotnet build
   dotnet run
   ```

4. The application will connect to the local SQL Server instance using the connection string specified in `appsettings.json`.

## Docker Deployment Steps

1. **Start the database container**:

   ```bash
   docker-compose up auth-server-db
   ```

2. **Run database migrations**:

   ```bash
   docker-compose up migrator
   ```

3. **Start all services**:

   ```bash
   docker-compose up
   ```

> **Note**: The migration step must be completed before starting the auth-server and other services.
