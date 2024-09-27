# RBAC Server

This is a Rust-based Role-Based Access Control (RBAC) server that manages user roles and permissions using PostgreSQL.

## Features

- **User Roles Management:** Assign and manage roles for users.
- **Role-Based Access Control (RBAC):** Define what actions each role can perform.
- **PostgreSQL Integration:** Uses PostgreSQL for storing users, roles, and permissions.
- **GraphQL API:** Efficient querying with GraphQL for frontend integration.
- **Rust Backend:** Fast and secure backend built using Rust.

## Getting Started

1. **Set up PostgreSQL:**

   Ensure that you have PostgreSQL installed and running. Create a new database for the application, and note down the connection string.

2. **Configure Database URL:**

   The database URL should be in the following format:

   ```bash
   postgres://<username>:<password>@<host>:<port>/<database>
3. **Start Server**
   ```bash
   cargo run -- -D "postgres://postgres:gaurav@localhost/"
