use sqlx::{PgPool, Pool, Postgres};

use crate::db::{
    permissions::init_permissions,
    roles::{init_role_permissions, init_roles},
    users::ensure_admin_exists,
};

pub async fn init_db(pool: &Pool<Postgres>) {
    let user_table = "
        CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL
        );
    ";

    let res = sqlx::query(&user_table)
        .execute(pool)
        .await
        .expect("Failed to create the user table");
    let roles_table = "CREATE TABLE IF NOT EXISTS roles (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL
        );";
    let res = sqlx::query(&roles_table)
        .execute(pool)
        .await
        .expect("Failed to create the roles table");

    let permissions_table = "CREATE TABLE IF NOT EXISTS permissions (
        id SERIAL PRIMARY KEY,
        action VARCHAR(255) NOT NULL
        );";
    let res = sqlx::query(&permissions_table)
        .execute(pool)
        .await
        .expect("Failed to create the permissions table");

    let user_role_table = "CREATE TABLE IF NOT EXISTS user_roles (
        user_id INTEGER REFERENCES users(id),
        role_id INTEGER REFERENCES roles(id),
        PRIMARY KEY (user_id, role_id)
        );
    ";
    let res = sqlx::query(&user_role_table)
        .execute(pool)
        .await
        .expect("Failed to create the user-role table");

    let role_permission_table = "CREATE TABLE IF NOT EXISTS role_permissions (
        role_id INTEGER REFERENCES roles(id),
        permission_id INTEGER REFERENCES permissions(id),
        PRIMARY KEY (role_id, permission_id)
        );
        ";
    let res = sqlx::query(&role_permission_table)
        .execute(pool)
        .await
        .expect("Failed to create the role-permission table");

    let check_user = sqlx::query(
        "
    SELECT id from users where lower(name) = 'admin';",
    )
    .fetch_optional(pool)
    .await
    .expect("Error:- Failed to chech the user");

    if check_user.is_some() {
        println!("database already configured");
        return;
    }
    init_roles(pool).await;
    init_permissions(pool).await;
    init_role_permissions(pool).await;
    ensure_admin_exists(pool).await;
}
