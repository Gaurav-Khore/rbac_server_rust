use async_graphql::{Error, ErrorExtensions};
use sqlx::{Pool, Postgres, Row};

pub async fn init_roles(pool: &Pool<Postgres>) {
    let qry = "INSERT INTO roles(name) VALUES ('Admin'),('Viewer'),('Editor')";

    let role_res = sqlx::query(&qry)
        .execute(pool)
        .await
        .expect("Error = Not able to Insert Role");
}

pub async fn insert_roles(pool: &Pool<Postgres>, name: String) -> async_graphql::Result<String> {
    let check_role = match sqlx::query(
        "
    select id from roles where name = $1",
    )
    .bind(&name)
    .fetch_optional(pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::new("Internal Server Error")
                .extend_with(|_, e| e.set("details", "Failed to check the role")));
        }
    };

    if check_role.is_some() {
        return Err(Error::new("Role Already Present")
            .extend_with(|_, e| e.set("details", "Role already Present")));
    }
    let qry = "INSERT INTO roles(name) VALUES ($1)";

    let ins_role = match sqlx::query(&qry).bind(&name).execute(pool).await {
        Ok(v) => v,
        Err(e) => {
            println!("Error insert_role:- {:?}", e);
            return Err(Error::new("Failed to Insert Role")
                .extend_with(|_, e| e.set("details", "Failed to insert user")));
        }
    };
    Ok(name)
}

pub async fn init_role_permissions(pool: &Pool<Postgres>) {
    // Admin roles-permission
    let roles = vec!["Create", "Update", "Read", "Delete"];
    let superuser_perm_role = "
    INSERT INTO role_permissions (role_id,permission_id) VALUES ((SELECT id FROM roles WHERE name = $1),
            (SELECT id FROM permissions WHERE action = $2) );
            ";
    for i in roles.iter() {
        let res = sqlx::query(&superuser_perm_role)
            .bind("Admin")
            .bind(i)
            .execute(pool)
            .await
            .expect("Failed to insert admin in role_permissions table");
    }

    // Editor roles-permission
    let roles = vec!["Update", "Read"];
    let superuser_perm_role = "
    INSERT INTO role_permissions (role_id,permission_id) VALUES ((SELECT id FROM roles WHERE name = $1),
            (SELECT id FROM permissions WHERE action = $2) );
            ";
    for i in roles.iter() {
        let res = sqlx::query(&superuser_perm_role)
            .bind("Editor")
            .bind(i)
            .execute(pool)
            .await
            .expect("Failed to insert editor in role_permissions table");
    }

    // Viewer roles-permission
    let roles = vec!["Read"];
    let superuser_perm_role = "
    INSERT INTO role_permissions (role_id,permission_id) VALUES ((SELECT id FROM roles WHERE name = $1),
            (SELECT id FROM permissions WHERE action = $2) );
            ";
    for i in roles.iter() {
        let res = sqlx::query(&superuser_perm_role)
            .bind("Viewer")
            .bind(i)
            .execute(pool)
            .await
            .expect("Failed to insert Viewer in roles table");
    }
}

pub async fn insert_role_permissions(
    pool: &Pool<Postgres>,
    role_name: String,
    permission: String,
) -> async_graphql::Result<()> {
    match sqlx::query(
        "INSERT INTO role_permissions (role_id,permission_id) VALUES ((SELECT id FROM roles WHERE name = $1),
            (SELECT id FROM permissions WHERE action = $2) );",
    )
    .bind(role_name)
    .bind(permission)
    .execute(pool)
    .await{
        Ok(v) => Ok(()),
        Err(e) => {
            println!("Error = {:?}",e);
            return Err(Error::new("Failed to Assign permissions to role").extend_with(|_,e| e.set("details", "Failed to insert permission for role")));
        }
    }
}

pub struct RolePermission {
    name: String,
    action: String,
}

pub async fn fetch_role_permission(
    pool: &Pool<Postgres>,
    role_name: Vec<String>,
) -> async_graphql::Result<Vec<String>> {
    let mut role_permissions: Vec<String> = vec![];
    for i in role_name {
        let qry = "select a.name,b.action from roles a, permissions b, role_permissions c where a.name like $1 and a.id= c.role_id and b.id = c.permission_id;";
        match sqlx::query(qry).bind(&i).fetch_all(pool).await {
            Ok(v) => {
                // let mut role_per: Vec<RolePermission> = Vec::new();
                for i in v {
                    role_permissions.push(i.get("action"));
                }
            }
            Err(e) => {
                println!("Error fetch_role_permission = {:?}", e);
                return Err(Error::new("Internal Server Error").extend_with(|_, e| {
                    e.set(
                        "details",
                        "Failed to fetch the roles permission for the user",
                    )
                }));
            }
        }
    }
    Ok(role_permissions)
}
