use async_graphql::{Context, Error, ErrorExtensions, Object};
use sqlx::{PgPool , Row};

use crate::{
    db::{
        permissions::{self, insert_permissions},
        roles::{fetch_role_permission, insert_role_permissions, insert_roles},
        users::{check_user_info, insert_role_user, insert_users},
    },
    utilities::{
        auth::authorize,
        jwt::{create_jwt, decode_jwt, Claims},
    },
};

pub struct Mutation;

#[Object]
impl Mutation {
    pub async fn add_user(
        &self,
        ctx: &Context<'_>,
        username: String,
        email: String,
        password: String,
    ) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();
        if !token.is_none() {
            let role_perm = match authorize(pool, token.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    println!("Error add_user:- {:?}", e);
                    return Err(e);
                }
            };
    
            if !role_perm.role.contains(&"Admin".to_string()) {
                return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "Not Authorized to add user")));
            }
        }

        match insert_users(pool, username.clone(), email, password).await {
            Ok(v) =>{ 
                match insert_role_user(pool, username.clone(), "Viewer".to_string()).await {
                    Ok(_) => Ok(format!("User {:?}, successfully added", username)),
                    Err(e) => {
                        return Err(e.into());
                    }
                }
                
        },
            Err(e) => {
                println!("Error add_user = {:?}", e);
                return Err(Error::new("Unable to Add User")
                    .extend_with(|_, x| x.set("details", "User with same name present")));
            }
        }
    }

    pub async fn add_role(&self, ctx: &Context<'_>, name: String) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();
        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error add_role:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.role.contains(&"Admin".to_string()) {
            return Err(Error::new("Not Authorized")
            .extend_with(|_, x| x.set("details", "Not Authorized to add Roles")));
        }

        match insert_roles(pool, name).await {
            Ok(v) => Ok(format!("Roled added :- {:?}", v)),
            Err(e) => Err(e),
        }
    }

    pub async fn assign_user_role(
        &self,
        ctx: &Context<'_>,
        username: String,
        roles: String,
    ) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error assign_user_role:- {:?}", e);
                return Err(e);
            }
        };

        if roles=="Admin".to_string() {
            return Err(Error::new("Can't Assign Admin role"));
        }

        if !role_perm.perm.contains(&"Update".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to add role")));
        }
            match insert_role_user(pool, username.clone(), roles).await {
                Ok(_) => (),
                Err(e) => {
                    println!("Error insert_role_user = {:?}", e);
                    return Err(e);
                }
        };
        Ok(format!(
            "Roles added successfully for user :- {:?}",
            username
        ))
    }

    pub async fn assign_role_permissions(
        &self,
        ctx: &Context<'_>,
        name: String,
        permissions: String,
    ) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error assign_user_role:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.perm.contains(&"Create".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to add role")));
        }
        match insert_role_permissions(pool, name.clone(), permissions).await {
                Ok(_) => (),
                Err(e) => {
                    println!("Error insert_role_user = {:?}", e);
                    return Err(e);
                }
            }
        Ok(format!(
            "Permissions added successfully for role :- {:?}",
            name
        ))
    }

    pub async fn delete_user_role(&self,ctx: &Context<'_>,user_name: String, role_name: String)  -> async_graphql::Result<String>  {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error delete_user_role:- {:?}", e);
                return Err(e);
            }
        };
        if role_name == "Admin".to_string() {
            return Err(Error::new("Admin Role Can't be deleted"));
        }
        let data = match sqlx::query("select count(1) from user_roles where user_id in (SELECT ID from USERS where name like $1);")
        .bind(&user_name).fetch_one(pool).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error getting count of userRole = {:?}",e);
                return Err(Error::new("INternal Server Error"));
            }
        };
        let count : i64 = data.get("count");
        if count == 1 {
            return Err(Error::new("Minimum One role required."));
        } 



        if !role_perm.perm.contains(&"Delete".to_string()){
            return Err(Error::new("Not Authorized")
            .extend_with(|_, x| x.set("details", "Not Authorized to add Permissions")));
        }

        match sqlx::query("DELETE FROM user_roles where user_id in (SELECT ID from USERS where name like $1) and role_id in (SELECT id FROM roles WHERE name like $2);")
        .bind(user_name)
        .bind(role_name).execute(pool).await {
            Ok(_) => (),
            Err(e) => {
                println!("Error delete user role = {:?}",e);
                return Err(Error::new("Unable to Delete Assigned Role"));
            }
        };
        

        Ok(format!("Successfuly deleted Role from User"))
    }

    pub async fn delete_role_permission(&self,ctx: &Context<'_>,role_name: String, action: String)-> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error delete_user_role:- {:?}", e);
                return Err(e);
            }
        };
        if role_name=="Admin".to_string() {
            return Err(Error::new("Admin Role can't be updated"));
        }
        let data = match sqlx::query("select count(1) from role_permissions where role_id in (SELECT ID from roles where name like $1);")
        .bind(&role_name).fetch_one(pool).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error getting count of userRole = {:?}",e);
                return Err(Error::new("INternal Server Error"));
            }
        };
        let count : i64 = data.get("count");
        if count == 1 {
            return Err(Error::new("Minimum One permission required."));
        } 
        if !role_perm.role.contains(&"Admin".to_string()){
            return Err(Error::new("Not Authorized")
            .extend_with(|_, x| x.set("details", "Not Authorized to add Permissions")));
        }

        match sqlx::query("DELETE FROM role_permissions where role_id in (SELECT ID from roles where name like $1) and permission_id in (SELECT id FROM permissions WHERE action like $2);")
        .bind(&role_name)
        .bind(&action).execute(pool).await {
            Ok(_) => (),
            Err(e) => {
                println!("Error delete role permission = {:?}",e);
                return Err(Error::new("Unable to Delete Assigned Perission"));
            }
        };

        Ok(format!("Permission successfully removed from role"))
    }


    pub async fn delete_user(&self,ctx: &Context<'_>,id: String)-> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error delete_user:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.role.contains(&"Admin".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to delete user")));
        }
        if role_perm.sub == id {
            return Err(Error::new("Admin User Can't be deleted"));
        }
        let id = id.parse::<i32>().unwrap();
        match sqlx::query("DELETE from USER_ROLES where user_id =$1").bind(id).execute(pool).await {
            Ok(_) => {
                match sqlx::query("DELETE from USERS where id = $1").bind(id).execute(pool).await {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Error at delete user ={:?}",e);
                        return Err(Error::new("Internal Server Error"));
                    } 
                }
            },
            Err(e) => {
                println!("Error at delete user user_role = {:?}",e);
                return Err(Error::new("Internal Server Error"));
            }
        }
        Ok("User Successfuly deleted".to_string())
    }

    pub async fn delete_role(&self,ctx: &Context<'_>,id:String) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error delete_role:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.role.contains(&"Admin".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to delete role")));
        }
        let id = id.parse::<i32>().unwrap();
        match sqlx::query("DELETE from role_permissions where role_id =$1").bind(id).execute(pool).await {
            Ok(_) => {
                match sqlx::query("DELETE from ROLES where id = $1").bind(id).execute(pool).await {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Error at delete role ={:?}",e);
                        return Err(Error::new("Internal Server Error"));
                    } 
                }
            },
            Err(e) => {
                println!("Error at delete user user_role = {:?}",e);
                return Err(Error::new("Internal Server Error"));
            }
        }
        Ok("User Successfuly deleted".to_string())
    }

    pub async fn update_password(&self, ctx: &Context<'_>,id:String,passwd:String) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error update_password:- {:?}", e);
                return Err(e);
            }
        };
        if id != role_perm.sub {
            return Err(Error::new("Not Authorized"));
        }
        let id = id.parse::<i32>().unwrap();
        let qry = "SELECT EXISTS (SELECT * FROM USERS WHERE id = $1);";
    let res = match sqlx::query(&qry).bind(&id).fetch_one(pool).await {
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

    match sqlx::query("UPDATE users SET password_hash= $1 where id = $2").bind(&passwd).bind(&id).execute(pool).await {
        Ok(_) => (),
        Err(e) => {
            println!("Error update password = {:?}",e);
            return Err(Error::new("Unable to change Password"));
        }
    }
        Ok("Password Successfully changed".to_string())
    }

    pub async fn update_role_name(&self,ctx: &Context<'_>,id:String,name:String) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error update_role_name:- {:?}", e);
                return Err(e);
            }
        };


        if !role_perm.role.contains(&"Admin".to_string()) {
            return Err(Error::new("Not Authorized")
                .extend_with(|_, x| x.set("details", "You are not authorized to update role")));
        }
        let id = id.parse::<i32>().unwrap();
        match sqlx::query("UPDATE roles set name=$1 where id = $2;").bind(&name).bind(&id).execute(pool).await {
            Ok(_)=>(),
            Err(e) => {
                println!("Error update Role = {:?}",e);
                return Err(Error::new("Unable to Update role"));
            }
        }
        Ok("Role name Successfully changes".to_string())
    }


    pub async fn update_user_name(&self,ctx: &Context<'_>,id:String,name:String) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error update_user_name:- {:?}", e);
                return Err(e);
            }
        };

        let id = id.parse::<i32>().unwrap();
        match sqlx::query("UPDATE users set name=$1 where id = $2;").bind(&name).bind(&id).execute(pool).await {
            Ok(_)=>(),
            Err(e) => {
                println!("Error update Name = {:?}",e);
                return Err(Error::new("Unable to Update User"));
            }
        }
        Ok("User name Successfully changed".to_string())
    }

    pub async fn update_user_role(&self,ctx: &Context<'_>,current_role:String,new_role: String,user_id:String) -> async_graphql::Result<String> {
        let token = ctx.data::<Option<String>>().unwrap();
        let pool = ctx.data::<PgPool>().unwrap();

        let role_perm = match authorize(pool, token.clone()).await {
            Ok(v) => v,
            Err(e) => {
                println!("Error update_user_name:- {:?}", e);
                return Err(e);
            }
        };

        if !role_perm.perm.contains(&"Update".to_string()) {
            return Err(Error::new("You are not authorized to update user role"));
        }
        let user_id = user_id.parse::<i32>().unwrap();
        match sqlx::query("UPDATE user_roles set role_id =(SELECT id from roles where name=$1 ) where user_id=$2 and role_id in (SELECT id from roles where name = $3);")
        .bind(&new_role).bind(&user_id).bind(current_role).execute(pool).await {
            Ok(_) => (),
            Err(e) => {
                print!("Error e = {:?}",e);
                return Err(Error::new("User Role Not updates"));
            }
        }

        Ok("User Role Updated Successfully".to_string())
    }
}
