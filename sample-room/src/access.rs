//! An optional shared password in front of the whole site.
//!
//! For putting the demo somewhere other people can reach, not for protecting anything that
//! matters: one password for everybody, checked against a SHA-256 the operator passes at
//! startup (`--access-hash`), so the password itself never appears on a command line or in
//! a process listing. The page, its modules and the room catalogue all sit behind it — the
//! catalogue names the rooms' DIDs, which is the one thing a stranger needs to start a join.
//!
//! The cookie is derived from the hash rather than minted per process, so restarting the
//! demo (which happens a lot) does not sign everybody out, and changing the password does.

use axum::Form;
use axum::extract::{FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const COOKIE: &str = "dr_access";
const LOGIN_PATH: &str = "/access";
pub(crate) const HEALTH_PATH: &str = "/health";

#[derive(Clone)]
pub(crate) struct Gate {
    hash: [u8; 32],
    token: String,
}

impl Gate {
    /// From the hex SHA-256 of the password. Refuses anything that is not exactly that, so a
    /// password pasted where its hash belongs fails at startup instead of locking everyone out.
    pub(crate) fn from_hex(hex: &str) -> Result<Self, String> {
        let hex = hex.trim().to_ascii_lowercase();
        let bytes = decode_hex(&hex).filter(|b| b.len() == 32).ok_or_else(|| {
            "--access-hash must be the 64-hex-character SHA-256 of the password \
             (make one with `--hash-password`)"
                .to_string()
        })?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        let token = to_hex(&Sha256::digest(
            [b"dataroom-demo/access\0".as_slice(), &hash].concat(),
        ));
        Ok(Gate { hash, token })
    }

    fn admits(&self, password: &str) -> bool {
        let got = Sha256::digest(password.as_bytes());
        // Constant time: the comparison should not say how much of the hash matched.
        got.iter()
            .zip(self.hash.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    fn has_cookie(&self, headers: &HeaderMap) -> bool {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|kv| kv.trim().split_once('='))
            .any(|(k, v)| k == COOKIE && v == self.token)
    }
}

/// The hex SHA-256 of `password`, as `--access-hash` expects it.
pub(crate) fn hash_password(password: &str) -> String {
    to_hex(&Sha256::digest(password.as_bytes()))
}

#[derive(Deserialize)]
struct Login {
    password: String,
}

pub(crate) async fn guard(State(gate): State<Gate>, req: Request, next: Next) -> Response {
    // The health check is the one path a balancer must reach without the password. It says
    // nothing a stranger could use: the process is up and its rooms are minted.
    if gate.has_cookie(req.headers()) || req.uri().path() == HEALTH_PATH {
        return next.run(req).await;
    }
    if req.method() == Method::POST && req.uri().path() == LOGIN_PATH {
        // Behind a TLS-terminating balancer the scheme is only visible in this header; the
        // cookie is `Secure` whenever the browser reached us over https.
        let secure = req
            .headers()
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https"));
        let password = match Form::<Login>::from_request(req, &()).await {
            Ok(Form(login)) => login.password,
            Err(_) => return login_page(StatusCode::BAD_REQUEST, Some("Enter the password.")),
        };
        if !gate.admits(&password) {
            // A pause per wrong guess, so the form is not a fast oracle.
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            eprintln!("access    refused a wrong password");
            return login_page(
                StatusCode::UNAUTHORIZED,
                Some("That password is not right."),
            );
        }
        let cookie = format!(
            "{COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000{}",
            gate.token,
            if secure { "; Secure" } else { "" }
        );
        let mut res = Redirect::to("/").into_response();
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            res.headers_mut().insert(header::SET_COOKIE, v);
        }
        return res;
    }
    login_page(StatusCode::UNAUTHORIZED, None)
}

fn login_page(status: StatusCode, error: Option<&str>) -> Response {
    let error = error
        .map(|e| format!(r#"<p class="err" role="alert">{e}</p>"#))
        .unwrap_or_default();
    let page = LOGIN_HTML.replace("{{ERROR}}", &error);
    (status, Html(page)).into_response()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

const LOGIN_HTML: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Data Rooms Demo</title><link rel="icon" href="data:,">
<style>
:root{color-scheme:light dark;--brand:#5b5bd6;--bg:light-dark(#f7f7fb,#0f0f14);--card:light-dark(#fff,#17171f);
--text:light-dark(#1a1a2e,#ececf3);--muted:light-dark(#5c5c70,#a3a3b5);--line:light-dark(#e3e3ec,#2a2a36);--err:light-dark(#b42318,#ff8a80)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--text);
font:16px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
background-image:radial-gradient(60rem 30rem at 15% -10%,rgba(91,91,214,.18),transparent 60%),radial-gradient(50rem 30rem at 100% 0%,rgba(232,138,228,.14),transparent 60%)}
form{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px;box-shadow:0 10px 30px rgba(20,20,60,.08)}
.mark{width:40px;height:40px;border-radius:10px;background:var(--brand);display:grid;place-items:center;margin-bottom:14px}
h1{font-size:1.25rem;margin:0 0 4px}p{margin:0 0 18px;color:var(--muted);font-size:.95rem}
input{width:100%;font:inherit;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:transparent;color:inherit}
input:focus{outline:2px solid var(--brand);outline-offset:1px}
button{margin-top:14px;width:100%;font:inherit;font-weight:600;padding:10px;border:0;border-radius:999px;background:var(--brand);color:#fff;cursor:pointer}
.err{color:var(--err);margin:12px 0 0;font-size:.9rem}
</style></head><body>
<form method="post" action="/access">
<div class="mark"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg></div>
<h1>Data Rooms Demo</h1>
<p>This demo is private. Enter the access password to continue.</p>
<input type="password" name="password" autocomplete="current-password" aria-label="Password" placeholder="Password" required autofocus>
{{ERROR}}
<button type="submit">Continue</button>
</form></body></html>"##;
