use regex::Regex;
use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};
use serde_enum_str::{Deserialize_enum_str, Serialize_enum_str};
use std::collections::HashMap;
use totp_rs::{Secret, TOTP};
use wasm_timer::{SystemTime, UNIX_EPOCH};
use worker::{kv::KvStore, *};

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum TwoFactorType {
    Totp,
    Otp,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    requires_two_factor_auth: Option<Vec<TwoFactorType>>,
}

#[derive(Serialize, Deserialize)]
struct Verify2FA {
    code: String,
}

#[derive(Deserialize)]
struct Verify2FAResponse {
    verified: bool,
}

#[derive(Deserialize_enum_str, Serialize_enum_str, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tag {
    // SystemNoCaptcha,
    // LanguageJpn,
    // SystemWorldAccess,
    // SystemAvatarAccess,
    // SystemFeedbackAccess,
    SystemTrustBasic,
    SystemTrustKnown,
    SystemTrustTrusted,
    SystemTrustVeteran,
    SystemTrustLegend,

    #[serde(other)]
    Other(String),
}

pub fn trust_color(tags: &Vec<Tag>) -> String {
    if tags.contains(&Tag::SystemTrustLegend) {
        // legend yellow
        "#FFFD54"
    } else if tags.contains(&Tag::SystemTrustVeteran) {
        // trusted purple
        "#784CDE"
    } else if tags.contains(&Tag::SystemTrustTrusted) {
        // known user orange
        "#EF8250"
    } else if tags.contains(&Tag::SystemTrustKnown) {
        // user green
        "#65CB6A"
    } else if tags.contains(&Tag::SystemTrustBasic) {
        // new user blue
        "#347AF6"
    } else {
        // visitor gray
        "#CCCCCC"
    }
    .to_string()
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum State {
    Offline,
    Active,
    Online,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Active,
    #[serde(rename = "join me")]
    JoinMe,
    #[serde(rename = "ask me")]
    AskMe,
    Busy,
    Offline,
}

pub trait User {
    fn id(&self) -> &String;
    fn bio(&self) -> &Option<String>;
    fn current_avatar_image_url(&self) -> &Option<String>;
    fn display_name(&self) -> &String;
    fn tags(&self) -> &Vec<Tag>;
    fn emoji(&self) -> String;
    fn status_description(&self) -> &Option<String>;
    fn user_icon(&self) -> &Option<String>;
}

fn empty_string_as_none<'de, D, T>(de: D) -> core::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    let opt = Option::<String>::deserialize(de)?;
    let opt = opt.as_ref().map(String::as_str);
    match opt {
        None | Some("") => Ok(None),
        Some(s) => T::deserialize(s.into_deserializer()).map(Some),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetUser {
    #[serde(deserialize_with = "empty_string_as_none")]
    bio: Option<String>,
    current_avatar_image_url: Option<String>,
    // current_avatar_thumbnail_image_url: Option<String>,
    id: String,
    display_name: String,
    tags: Vec<Tag>,
    status: Status,
    // state: State,
    #[serde(deserialize_with = "empty_string_as_none")]
    status_description: Option<String>,
    #[serde(deserialize_with = "empty_string_as_none")]
    user_icon: Option<String>,
}

impl User for GetUser {
    fn bio(&self) -> &Option<String> {
        &self.bio
    }
    fn current_avatar_image_url(&self) -> &Option<String> {
        &self.current_avatar_image_url
    }
    fn display_name(&self) -> &String {
        &self.display_name
    }
    fn emoji(&self) -> String {
        status_emoji(&self.status).to_string()
    }
    fn id(&self) -> &String {
        &self.id
    }
    fn tags(&self) -> &Vec<Tag> {
        &self.tags
    }
    fn status_description(&self) -> &Option<String> {
        &self.status_description
    }
    fn user_icon(&self) -> &Option<String> {
        &self.user_icon
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchUser {
    #[serde(deserialize_with = "empty_string_as_none")]
    bio: Option<String>,
    current_avatar_image_url: Option<String>,
    // current_avatar_thumbnail_image_url: Option<String>,
    id: String,
    display_name: String,
    tags: Vec<Tag>,
    status: Status,
    #[serde(deserialize_with = "empty_string_as_none")]
    status_description: Option<String>,
    #[serde(deserialize_with = "empty_string_as_none")]
    user_icon: Option<String>,
}

impl User for SearchUser {
    fn bio(&self) -> &Option<String> {
        &self.bio
    }
    fn current_avatar_image_url(&self) -> &Option<String> {
        &self.current_avatar_image_url
    }
    fn display_name(&self) -> &String {
        &self.display_name
    }
    fn emoji(&self) -> String {
        status_emoji(&self.status).to_string()
    }
    fn id(&self) -> &String {
        &self.id
    }
    fn tags(&self) -> &Vec<Tag> {
        &self.tags
    }
    fn status_description(&self) -> &Option<String> {
        &self.status_description
    }
    fn user_icon(&self) -> &Option<String> {
        &self.user_icon
    }
}

fn status_emoji(status: &Status) -> &str {
    match status {
        Status::Active => "\u{1F7E2}",
        Status::AskMe => "\u{1F7E0}",
        Status::Busy => "\u{1F534}",
        Status::JoinMe => "\u{1F535}",
        Status::Offline => "\u{26AB}",
    }
}

type SearchUserResp = Vec<SearchUser>;

#[derive(Serialize, Deserialize)]
pub struct VRCApi {
    auth_cookie: Option<String>,
    twofactor_cookie: Option<String>,
    credentials: Option<String>,
    totp: Option<TOTP>,
}
impl VRCApi {
    fn new(
        auth_cookie: Option<String>,
        credentials: Option<String>,
        twofactor_cookie: Option<String>,
        totp: Option<TOTP>,
    ) -> Self {
        Self {
            auth_cookie,
            credentials,
            twofactor_cookie,
            totp,
        }
    }

    pub async fn auth(
        self: &mut Self, // cookie: Option<String>,
                         // credentials: Option<String>,
                         // totp: Option<TOTP>,
    ) -> Result<()> {
        // let mut init = RequestInit::new();
        let mut headers = Headers::new();
        headers.set("user-agent", "profile/1.0")?;

        if let Some(cookie) = &self.auth_cookie {
            headers.set("cookie", &format!("auth={}", cookie))?;
        }

        if let Some(credentials) = &self.credentials {
            headers.set("authorization", &format!("Basic {}", credentials))?;
        }

        let req = Request::new_with_init(
            "https://api.vrchat.cloud/api/1/auth/user",
            RequestInit::new()
                .with_method(Method::Get)
                .with_headers(headers.clone()),
        )?;
        let mut resp = Fetch::Request(req).send().await?;

        if resp.status_code() != 200 {
            console_log!("auth failed. headers: {:?} ", resp.headers());
            return Err(format!("error with login endpoint: {}", resp.text().await?).into());
        }

        if let Some(set_cookie) = resp.headers().get("set-cookie")? {
            if let Some(auth) = Regex::new("auth=([^;]+);")
                .unwrap()
                .captures(&set_cookie)
                .unwrap()
                .get(1)
            {
                self.auth_cookie = Some(auth.as_str().to_owned());
            }
        };

        let login_resp = resp.json::<LoginResponse>().await?;
        if let Some(twofactor_methods) = login_resp.requires_two_factor_auth {
            if twofactor_methods.contains(&TwoFactorType::Totp) {
                if !self.totp_auth().await? {
                    return Err("totp authentication failed".into());
                }
            } else {
                return Err("totp is unavailable".into());
            }
        };

        Ok(())
    }

    pub async fn totp_auth(self: &mut Self) -> Result<bool> {
        let totp = self
            .totp
            .as_ref()
            .ok_or("totp was requested but no secret was provided")?;

        // console_log!("{}", totp.generate().map_err(|e: std::time::SystemTimeError| e.to_string())?);
        let totp_body = serde_json::to_string(&Verify2FA {
            code: totp.generate(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system time error")?
                    .as_secs(),
            ),
        })
        .map_err(|e| e.to_string())?;

        let totp_req = Request::new_with_init(
            "https://api.vrchat.cloud/api/1/auth/twofactorauth/totp/verify",
            RequestInit::new()
                .with_method(Method::Post)
                .with_headers(self.headers_json())
                .with_body(Some(totp_body.into())),
        )?;
        let mut totp_resp = Fetch::Request(totp_req).send().await?;

        if totp_resp.status_code() != 200 {
            console_log!("two factor failed. headers: {:?} ", totp_resp.headers());
            return Err(format!("error with totp endpoint: {}", totp_resp.text().await?).into());
        }

        if !totp_resp.json::<Verify2FAResponse>().await?.verified {
            return Ok(false);
        }

        self.twofactor_cookie = Some(
            Regex::new("twoFactorAuth=([^;]+);")
                .unwrap()
                .captures(
                    totp_resp
                        .headers()
                        .get("set-cookie")?
                        .ok_or("failed to get set-cookie header")?
                        .as_str(),
                )
                .unwrap()
                .get(1)
                .ok_or("failed to get twoFactorAuth cookie")?
                .as_str()
                .to_owned(),
        );

        Ok(true)
    }

    pub async fn search_user(self: &Self, search: String, n: u8) -> Result<SearchUserResp> {
        let req = Request::new_with_init(
            Url::parse_with_params(
                "https://api.vrchat.cloud/api/1/users",
                &[("search", search), ("n", n.to_string())],
            )?
            .as_str(),
            RequestInit::new()
                .with_method(Method::Get)
                .with_headers(self.headers()),
        )?;
        let mut resp = Fetch::Request(req).send().await?;

        if resp.status_code() != 200 {
            console_log!("{}, {:?}", resp.text().await?, self.headers());
            return Err(format!("unexpect status: {}", resp.status_code()).into());
        }

        resp.json::<SearchUserResp>().await
    }

    pub async fn get_user_by_id(self: &Self, id: &String) -> Result<Option<GetUser>> {
        let req = Request::new_with_init(
            format!("https://api.vrchat.cloud/api/1/users/{}", id).as_str(),
            RequestInit::new()
                .with_method(Method::Get)
                .with_headers(self.headers()),
        )?;
        let mut resp = Fetch::Request(req).send().await?;

        match resp.status_code() {
            200 => resp.json::<Option<GetUser>>().await,
            404 => Ok(None),
            _ => {
                console_log!("{}, {:?}", resp.text().await?, self.headers());
                Err(format!("unexpect status: {}", resp.status_code()).into())
            }
        }
    }

    pub async fn with_kv(kv: KvStore, credentials: String, totp: Option<TOTP>) -> Result<Self> {
        return Ok(match kv.get("vrcapi_client").text().await? {
            Some(client_data) => {
                let mut client = serde_json::from_str::<VRCApi>(client_data.as_str())?;
                client.auth().await?;

                let serded_data = serde_json::to_string(&client)?;

                if serded_data != client_data {
                    kv.put("vrcapi_client", serded_data)?.execute().await?;
                }

                client
            }
            None => {
                let mut client = Self::new(None, Some(credentials), None, totp);
                client.auth().await?;

                kv.put("vrcapi_client", serde_json::to_string(&client)?)?
                    .execute()
                    .await?;

                client
            }
        });
    }

    pub async fn with_context(ctx: RouteContext<()>) -> Result<Self> {
        let totp = match ctx.var("totp_secret") {
            Ok(totp) => Some(
                TOTP::new(
                    totp_rs::Algorithm::SHA1,
                    6,
                    1,
                    30,
                    Secret::Encoded(totp.to_string()).to_bytes().unwrap(),
                )
                .map_err(|e| Error::RustError(e.to_string()))?,
            ),
            _ => None,
        };
        Self::with_kv(
            ctx.kv("authstore")?,
            ctx.var("credentials")?.to_string(),
            totp,
        )
        .await
    }

    fn headers(self: &Self) -> Headers {
        let mut hash_cookies: HashMap<_, _> = HashMap::new();
        hash_cookies.insert("auth", self.auth_cookie.clone().unwrap());
        if let Some(tfa) = self.twofactor_cookie.clone() {
            hash_cookies.insert("twoFactorAuth", tfa);
        }

        let mut headers = Headers::new();
        headers.set("user-agent", "profile/1.0").unwrap();
        headers
            .set(
                "cookie",
                &hash_cookies
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<String>>()
                    .join(";"),
            )
            .unwrap();

        headers
    }

    fn headers_json(self: &Self) -> Headers {
        let mut headers = self.headers();
        headers.set("content-type", "application/json").unwrap();

        headers
    }
}
