use async_graphql::{Error, ErrorExtensions};
use sqlx::{Pool, Postgres};

pub async fn init_permissions(pool: &Pool<Postgres>) {

    let qry = "INSERT INTO permissions(action) VALUES ('Create'),('Update'),('Delete'),('Read');";

    let permission_res = sqlx::query(&qry)
        .execute(pool)
        .await
        .expect("Error = Failed to initialize permissions");
}

pub async fn insert_permissions(
    pool: &Pool<Postgres>,
    action: String,
) -> async_graphql::Result<String> {

    let check_perm = match sqlx::query(
        "
    SELECT id from PERMISSIONS where action = $1",
    )
    .bind(&action)
    .fetch_optional(pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            println!("Error insert_permissions :- {:?}", e);
            return Err(Error::new("Permission Check Failed")
                .extend_with(|_, e| e.set("details", "Failed to check the permission")));
        }
    };

    if check_perm.is_some() {
        return Err(Error::new("Failed to Insert")
            .extend_with(|_, e| e.set("details", "Permission already present")));
    }

    let qry = "INSERT INTO permissions(action) VALUES ($1)";
    let ins_perm = match sqlx::query(&qry).bind(&action).execute(pool).await {
        Ok(v) => v,
        Err(e) => {
            println!("Error:- Failed to insert the permission {:?}", &action);
            return Err(Error::new("Failed to Insert")
                .extend_with(|_, e| e.set("details", "Failed to insert Permission")));
        }
    };
    Ok(action)
}
