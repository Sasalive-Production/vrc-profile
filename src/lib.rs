use regex::Regex;
use std::collections::HashMap;
use vrc::*;
use worker::{Result, *};

mod vrc;

fn format_error(message: impl Into<String>, status_code: u16) -> Result<Response> {
    Ok(Response::from_html(format!(
        "<meta charset='utf-8' /><meta property='og:title' content='Error: {0}' />{0}",
        html_escape::encode_text(&message.into())
    ))
    .unwrap()
    .with_status(status_code))
}

fn format_user(user: &impl User) -> Result<Response> {
    let mut t = format!(
        "<meta charset='utf-8' /><meta property='og:title' content='{0}{1}' /><meta property='og:type' content='website' /><meta name='theme-color' content='{2}' /><meta property='og:site_name' content='VRChatプロフィール' /><meta property='og:url' content='{3}'><meta http-equiv='refresh' content='0; URL={3}'>",user.emoji(), user.display_name(), trust_color(&user.tags()), format!("https://vrchat.com/home/user/{}", user.id())
    );
    if let Some(icon) = &user
        .user_icon()
        .as_ref()
        .or(user.current_avatar_image_url().as_ref())
    {
        t.push_str(&format!("<meta property='og:image:width' content='1200'><meta property='og:image:height' content='630'><meta property='og:image' content='{0}' />", icon))
    };

    let mut bio_content = if let Some(status_description) = user.status_description() {
        format!("{}\n---\n", status_description).to_string()
    } else {
        "".to_string()
    };

    bio_content.push_str(if let Some(bio) = &user.bio() {
        bio.as_str()
    } else {
        "No bio."
    });

    t.push_str(&format!(
        "<meta property='og:description' content='{0}'>",
        html_escape::encode_text(&bio_content)
    ));

    let resp = Response::from_html(t).unwrap();
    let mut headers = resp.headers().clone();
    headers.set("cache-control", "max-age=300")?;
    headers.set("content-type", "text/html;charset=utf-8")?;

    Ok(resp.with_headers(headers))
}
#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let mut router = Router::new();
    router = router
        .get_async("/", |req, ctx| async move {
            let hash_query: HashMap<_, _> = req.url()?.query_pairs().into_owned().collect();
            if let Some(search) = hash_query.get("search") {
                let client = VRCApi::with_context(ctx).await?;

                if let Some(user) = client
                    .search_user(search.to_string(), 1)
                    .await?
                    .iter()
                    .next()
                {
                    format_user(user)
                } else {
                    format_error("User not found.", 404)
                }
            } else {
                format_error("'search' parameter is required.", 400)
            }
        })
        .get_async("/:id", |_req, ctx| async move {
            let usr_id = Regex::new(
                "^usr_([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$",
            )
            .unwrap()
            .captures(ctx.param("id").ok_or("failed to get id param")?)
            .ok_or("bad id")?
            .get(0)
            .ok_or("bad id")?
            .as_str()
            .to_owned();

            let client = VRCApi::with_context(ctx).await?;
            if let Some(user) = &client.get_user_by_id(&usr_id).await? {
                format_user(user)
            } else {
                let resp = format_error("User a not found.", 404).unwrap();
                let mut headers = resp.headers().clone();
                headers.set("cache-control", "max-age=31536000")?;

                Ok(resp.with_headers(headers))
            }
        })
        .get_async("/t/:alias", |_req, ctx| async move {
            let aliases = serde_json::from_str::<HashMap<String, String>>(
                ctx.var("aliases")?.to_string().as_str(),
            )?;
            if let Some(usr_id) = aliases.get(ctx.param("alias").unwrap()) {
                let client = VRCApi::with_context(ctx).await?;
                format_user(
                    &client
                        .get_user_by_id(usr_id)
                        .await?
                        .ok_or("User a not found.")?,
                )
            } else {
                let resp = format_error("Alias a not found.", 404).unwrap();
                let mut headers = resp.headers().clone();
                headers.set("cache-control", "max-age=3600")?;

                Ok(resp.with_headers(headers))
            }
        });
    // .get_async("/debug", |_req, ctx| async move {
    //     let client = VRCApi::with_context(ctx).await?;
    //     Response::ok(format!("{:?}", serde_json::to_string(&client)?))
    // })
    // .get_async("/cookie", |_, ctx| async move {
    //     Response::ok(format!(
    //         "{:?}",
    //         ctx.kv("authstore")?.get("vrcapi_authcookie").text().await?
    //     ))
    // });

    match router.run(req, env).await {
        Err(e) => Response::error(format!("internal error: {}", e), 500),
        Ok(r) => Ok(r),
    }
}
