use async_graphql::{Error, ErrorExtensions};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{Pool, Postgres, Row};

pub async fn insert_users(
    pool: &Pool<Postgres>,
    name: String,
    email: String,
    passwd: String,
) -> Result<(), Error> {
    let check_res = match sqlx::query(
        "
    Select id from USERS where name = $1;",
    )
    .bind(&name)
    .fetch_optional(pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return Err(e.into());
        }
    };

    if check_res.is_some() {
        return Err("User Already Presnet".into());
    }

    match sqlx::query(
        "
    INSERT INTO users(name,email,password_hash) VALUES ($1,$2,$3)",
    )
    .bind(&name)
    .bind(&email)
    .bind(&passwd)
    .execute(pool)
    .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            return Err(e.into());
        }
    }
}

pub async fn ensure_admin_exists(pool: &Pool<Postgres>) {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"gaurav")
    .expect("HMAC can take key of any size");
    mac.update(b"Admin");
    let passwd = hex::encode(mac.finalize().into_bytes());
    insert_users(
        pool,
        "Admin".to_string(),
        "admin@test.com".to_string(),
        passwd,
    )
    .await
    .expect("Failed to insert admin user");
    insert_role_user(pool, "Admin".to_string(), "Admin".to_string())
        .await
        .expect("Faild to assign admin a role");
}

pub async fn insert_role_user(
    pool: &Pool<Postgres>,
    username: String,
    role: String,
) -> async_graphql::Result<()> {
    match sqlx::query(
        "INSERT INTO user_roles (user_id,role_id) VALUES (
        (SELECT id from users where name = $1), (SELECT id from roles where name = $2)
        );",
    )
    .bind(username)
    .bind(role)
    .execute(pool)
    .await
    {
        Ok(v) => Ok(()),
        Err(e) => {
            println!("Error = {:?}", e);
            return Err(Error::new("Role not found")
                .extend_with(|_, e| e.set("details", "Failed to insert role for user")));
        }
    }
}

pub struct UserInfo {
    pub status: bool,
    pub status_message: String,
    pub id: i32,
    pub email: String,
    pub role: Vec<String>,
}
pub async fn check_user_info(
    pool: &Pool<Postgres>,
    email: String,
    passwd: String,
) -> async_graphql::Result<UserInfo> {
    let qry = "SELECT EXISTS (SELECT * FROM USERS WHERE email = $1);";
    let res = match sqlx::query(&qry).bind(&email).fetch_one(pool).await {
        Ok(v) => v,
        Err(e) => {
            return Err(Error::new("User Does not exists")
                .extend_with(|_, e| e.set("details", "User Not Found")));
        }
    };
    let user_exists: bool = res.get("exists");
    if !user_exists {
        return Err(Error::new("User Does not exists")
            .extend_with(|_, e| e.set("details", "User Not Found")));
    }

    let qry = "SELECT a.id,a.password_hash,c.name from users a , user_roles b, roles c where a.id = b.user_id and b.role_id =c.id  and a.email=$1;";
    let res = sqlx::query(&qry)
        .bind(&email)
        .fetch_all(pool)
        .await
        .expect("Error:- Failed to fetch the id and password hash");
    let db_passwd: String = res.get(0).unwrap().get("password_hash");
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"gaurav").expect("HMAC can take key of any size");
    mac.update(passwd.as_bytes());
    let passwd = hex::encode(mac.finalize().into_bytes());
    if passwd != db_passwd {
        return Err(
            Error::new("Wrong Password").extend_with(|_, e| e.set("details", "Wrong Credentials"))
        );
    }
    let uid: i32 = res.get(0).unwrap().get("id");
    let mut roles: Vec<String> = Vec::new();
    for row in res.iter() {
        roles.push(row.get("name"));
    }
    return Ok(UserInfo {
        status: true,
        status_message: "Correct Credentials".to_string(),
        id: uid,
        email,
        role: roles,
    });
}
