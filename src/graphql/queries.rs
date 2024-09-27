use std::{collections::HashMap, string};

use actix_web::{http::header::HeaderValue, HttpRequest};
use async_graphql::{Context, Data, Error, ErrorExtensions, Object};
use sqlx::{PgPool, Row};

use crate::{
    db::{roles::fetch_role_permission, users::check_user_info},
    utilities::{auth::authorize, jwt::create_jwt},
};

#[derive(sqlx::FromRow, async_graphql::SimpleObject)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
}

#[derive(sqlx::FromRow, async_graphql::SimpleObject)]
pub struct Roles {
    pub id: i32,
    pub name: String,
}

#[derive(sqlx::FromRow, async_graphql::SimpleObject)]
pub struct Permissions {
    pub id: i32,
    pub action: String,
}

#[derive(sqlx::FromRow, async_graphql::SimpleObject)]
pub struct TokenData {
    pub token: String,
    pub id: String,
}

#[derive(sqlx::FromRow, async_graphql::SimpleObject)]
pub struct RolePermi {
    pub role: String,
    pub perm: Vec<String>
}

#[derive(sqlx::FromRow, async_graphql::SimpleObject)]
pub struct RoleUsers {
    pub user_id: i32,
    pub user_name: String,
    pub user_email: String
}
pub struct Query;
#[Object]
impl Query {
    pub async fn fetch_testing(&self) -> String {
        "Hello".to_string()
    }

    pub async fn login(
        &self,
        ctx: &Context<'_>,
        email: String,
        password: String,
    ) -> async_graphql::Result<TokenData> {
        let pool = ctx.data::<PgPool>().unwrap();
        match check_user_info(pool, email.to_string(), password.to_string()).await {
            Ok(v) => {
                let uid = format!("{}", v.id);
                let role = v.role;
                // call the jwt token function
                match create_jwt(&uid, role).await {
                    Ok(v) => Ok(TokenData { token: v , id: uid.clone()}),
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn fetch_all_user(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<User>> {
        // let token = ctx.data::<String>().unwrap();
        let db_pool = ctx.data::<PgPool>().unwrap();
        let token = ctx.data::<Option<String>>().unwrap();
        let role_perm = match authorize(db_pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error assign_user_role:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.perm.contains(&"Read".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to view users")));
        }
        let data = match sqlx::query("SELECT id,name,email from users order by id;")
            .fetch_all(db_pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::new("Intenal Server Error")
                    .extend_with(|_, x| x.set("details", " Failed to fetch the users")));
            }
        };
        let mut res: Vec<User> = vec![];
        for i in data {
            let id: i32 = i.get("id");
            let name: String = i.get("name");
            let email: String = i.get("email");
            res.push(User { id, name, email });
        }
        Ok(res)
    }

    pub async fn fetch_user(&self, ctx: &Context<'_>, id: String) -> async_graphql::Result<User> {
        let db_pool = ctx.data::<PgPool>().unwrap();
        let token = ctx.data::<Option<String>>().unwrap();
        // let id = id.parse::<i32>()
        let role_perm = match authorize(db_pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error fetch_user:- {:?}", e);
                return Err(e);
            }
        };
        let id = id.parse::<i32>().unwrap();
        if !role_perm.role.contains(&"Admin".to_string()) {
            let check_exist = match sqlx::query("select  Exists (select * from user_roles a , roles b where a.role_id = b.id and a.user_id=$1 and b.name LIKE 'Admin');").bind(&id).fetch_one(db_pool).await {
                Ok(v) => v,
                Err(e) => {
                    println!("Error fetch user = {:?}",e);
                    return Err(Error::new("Internal Server Error"));
                }
            };
            let exist : bool= check_exist.get("exists");
            if exist {
                return Err(Error::new("Not Authorized"));
            }
            else {
                match sqlx::query("SELECT id,name,email from users where id = $1;")
            .bind(id)
            .fetch_one(db_pool)
            .await
        {
            Ok(v) => {
                return Ok(User {
                id: v.get("id"),
                name: v.get("name"),
                email: v.get("email"),});
                },
            Err(e) => {return Err(Error::new("User Not Found")
                .extend_with(|_, x| x.set("details", "User with the following id not found")));}
        }
            }
        }
        else {match sqlx::query("SELECT id,name,email from users where id = $1;")
            .bind(id)
            .fetch_one(db_pool)
            .await
        {
            Ok(v) => {
                return Ok(User {
                id: v.get("id"),
                name: v.get("name"),
                email: v.get("email"),});
                },
            Err(e) => {return Err(Error::new("User Not Found")
                .extend_with(|_, x| x.set("details", "User with the following id not found")));}
        }}
    }

    async fn fetch_all_roles(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<Roles>> {
        let db_pool = ctx.data::<PgPool>().unwrap();
        let token = ctx.data::<Option<String>>().unwrap();

        let role_perm = match authorize(db_pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error assign_user_role:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.perm.contains(&"Read".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to View Role")));
        }
        let data = match sqlx::query("SELECT id,name from roles order by id;")
            .fetch_all(db_pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::new("Intenal Server Error")
                    .extend_with(|_, x| x.set("details", " Failed to fetch the Roles")));
            }
        };

        let mut res: Vec<Roles> = vec![];

        for i in data {
            let id: i32 = i.get("id");
            let name: String = i.get("name");
            res.push(Roles { id, name });
        }
        Ok(res)
    }

    async fn fetch_all_permissions(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Vec<Permissions>> {
        let db_pool = ctx.data::<PgPool>().unwrap();
        let token = ctx.data::<Option<String>>().unwrap();

        let role_perm = match authorize(db_pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error assign_user_role:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.perm.contains(&"Read".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to view permissions")));
        }
        let data = match sqlx::query("SELECT id,action from permissions order by id;")
            .fetch_all(db_pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::new("Intenal Server Error")
                    .extend_with(|_, x| x.set("details", " Failed to fetch the permissions")));
            }
        };

        let mut res: Vec<Permissions> = vec![];

        for i in data {
            let id: i32 = i.get("id");
            let action: String = i.get("action");
            res.push(Permissions { id, action });
        }
        Ok(res)
    }


    async fn fetch_user_role_permission(&self,ctx: &Context<'_>,id: String) -> async_graphql::Result<Vec<RolePermi>>{
        let db_pool = ctx.data::<PgPool>().unwrap();
        let token = ctx.data::<Option<String>>().unwrap();

        let role_perm = match authorize(db_pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error authorize_user_role_permission:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.perm.contains(&"Read".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to view permissions")));
        }
        let id = id.parse::<i32>().unwrap();
        let data = match sqlx::query("select a.user_id, c.name,d.action from user_roles a, role_permissions b, roles c, permissions d where a.role_id = b.role_id and b.permission_id = d.id and a.role_id = c.id and a.user_id = $1;")
        .bind(id)
        .fetch_all(db_pool).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error fetch_user_role_permission = {:?}",e);
                return Err(Error::new("Intenal Server Error")
                    .extend_with(|_, x| x.set("details", " Failed to fetch the permissions")));
            }
        };
        let mut dum:HashMap<String, Vec<String>> = HashMap::new();
        for i in data {
            let name: String = i.get("name");
            let action : String = i.get("action");
            if !dum.contains_key(&name) {
                dum.insert(name.clone(), vec![]);
            }

            dum.get_mut(&name).unwrap().push(action.clone());
        }

        let mut res: Vec<RolePermi> = Vec::new();
        for (i,j) in dum.iter() {
            res.push( RolePermi {
                role: i.clone(),
                perm: j.clone()
            });
        }
        Ok(res)
    }

    async fn fetch_role_users(&self, ctx: &Context<'_>, role_name:String) -> async_graphql::Result<Vec<RoleUsers>> {
        let db_pool = ctx.data::<PgPool>().unwrap();
        let token = ctx.data::<Option<String>>().unwrap();

        let role_perm = match authorize(db_pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error fetch_role:- {:?}", e);
                return Err(e);
            }
        };
        if !role_perm.role.contains(&"Admin".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to view roles")));
        }
        // let role_id = role_id.parse::<i32>().unwrap();
        let data = match sqlx::query("select b.id,b.name,b.email from user_roles a, users b where a.user_id = b.id and a.role_id in (SELECT id from roles where name=$1);").bind(&role_name).fetch_all(db_pool).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error fetch role");
                return Err(Error::new("Internal Server Error"));
            }
        };
        let mut res : Vec<RoleUsers> = Vec::new();

        for i in data {
            res.push(RoleUsers {
                user_id: i.get("id"),
                user_name: i.get("name"),
                user_email: i.get("email")
            });
        }

        Ok(res)
    }

    async fn fetch_role_all_permissions(&self,ctx: &Context<'_>,role_name:String) -> async_graphql::Result<Vec<String>> {
        let db_pool = ctx.data::<PgPool>().unwrap();
        let token = ctx.data::<Option<String>>().unwrap();

        let role_perm = match authorize(db_pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error fetch_role:- {:?}", e);
                return Err(e);
            }
        };
        if !role_perm.role.contains(&"Admin".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to view roles")));
        }

        match fetch_role_permission(db_pool,vec![role_name.clone()]).await {
            Ok(v) => Ok(v),
            Err(e) => {
                return Err(e)
            }
        }
    }
}


