//! Minimal uniquely-addressed D-Bus boundary for the GlobalShortcuts portal.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock,
    },
    time::Duration,
};

use ashpd::{
    zbus::{
        self,
        proxy::SignalStream as ZbusSignalStream,
        zvariant::{as_value, ObjectPath, OwnedObjectPath, OwnedValue, Type},
        Connection, Proxy,
    },
    AppID, WindowIdentifier,
};
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Deserializer, Serialize};

const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const REGISTRY_INTERFACE: &str = "org.freedesktop.host.portal.Registry";
const GLOBAL_SHORTCUTS_INTERFACE: &str = "org.freedesktop.portal.GlobalShortcuts";
const REQUEST_INTERFACE: &str = "org.freedesktop.portal.Request";
const SESSION_INTERFACE: &str = "org.freedesktop.portal.Session";
const REQUEST_PATH_PREFIX: &str = "/org/freedesktop/portal/desktop/request";
const SESSION_PATH_PREFIX: &str = "/org/freedesktop/portal/desktop/session";

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static TOKEN_NONCE: LazyLock<Result<u128, String>> = LazyLock::new(|| {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("Failed to generate portal handle-token nonce: {error}"))?;
    Ok(u128::from_le_bytes(bytes))
});

pub type SignalStream<T> = Pin<Box<dyn Stream<Item = Result<T, String>> + Send + 'static>>;

#[derive(Debug, Serialize, Type, Default)]
#[zvariant(signature = "dict")]
struct EmptyOptions {}

#[derive(Debug, Serialize, Type)]
#[zvariant(signature = "dict")]
struct CreateSessionOptions {
    #[serde(with = "as_value")]
    handle_token: String,
    #[serde(with = "as_value")]
    session_handle_token: String,
}

#[derive(Debug, Serialize, Type)]
#[zvariant(signature = "dict")]
struct BindShortcutsOptions {
    #[serde(with = "as_value")]
    handle_token: String,
}

#[derive(Debug, Serialize, Type)]
pub struct NewShortcut(String, WireNewShortcutInfo);

#[derive(Debug, Serialize, Type)]
#[zvariant(signature = "dict")]
struct WireNewShortcutInfo {
    #[serde(with = "as_value")]
    description: String,
    #[serde(with = "as_value")]
    preferred_trigger: String,
}

#[derive(Debug, Deserialize, Type)]
struct WireBoundShortcut(String, WireBoundShortcutInfo);

#[derive(Debug, Deserialize, Type)]
#[zvariant(signature = "dict")]
struct WireBoundShortcutInfo {
    #[serde(with = "as_value")]
    description: String,
    #[serde(with = "as_value")]
    trigger_description: String,
}

#[derive(Debug, Deserialize, Type)]
#[zvariant(signature = "dict")]
struct BindResponse {
    #[serde(with = "as_value")]
    shortcuts: Vec<WireBoundShortcut>,
}

#[derive(Debug, Type)]
#[zvariant(signature = "dict")]
struct CreateSessionResponse {
    session_handle: OwnedObjectPath,
}

impl<'de> Deserialize<'de> for CreateSessionResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut values = HashMap::<String, OwnedValue>::deserialize(deserializer)?;
        let value = values.remove("session_handle").ok_or_else(|| {
            serde::de::Error::custom("CreateSession response is missing session_handle")
        })?;
        let session_handle = if let Ok(path) = <&ObjectPath<'_>>::try_from(&value) {
            OwnedObjectPath::from(ObjectPath::to_owned(path))
        } else if let Ok(path) = <&str>::try_from(&value) {
            OwnedObjectPath::try_from(path).map_err(|error| {
                serde::de::Error::custom(format!("Invalid session_handle object path: {error}"))
            })?
        } else {
            return Err(serde::de::Error::custom(
                "session_handle must have D-Bus type s or o",
            ));
        };
        Ok(Self { session_handle })
    }
}

impl NewShortcut {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        preferred_trigger: impl Into<String>,
    ) -> Self {
        Self(
            id.into(),
            WireNewShortcutInfo {
                description: description.into(),
                preferred_trigger: preferred_trigger.into(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundShortcut {
    pub id: String,
    pub description: String,
    pub trigger_description: String,
}

impl From<WireBoundShortcut> for BoundShortcut {
    fn from(value: WireBoundShortcut) -> Self {
        Self {
            id: value.0,
            description: value.1.description,
            trigger_description: value.1.trigger_description,
        }
    }
}

#[derive(Debug)]
pub struct ShortcutSignal {
    pub session_path: OwnedObjectPath,
    pub shortcut_id: String,
}

#[derive(Debug)]
pub struct ShortcutsChangedSignal {
    pub session_path: OwnedObjectPath,
    pub shortcuts: Vec<BoundShortcut>,
}

#[derive(Debug)]
pub enum PortalSignal {
    Activated(ShortcutSignal),
    Deactivated(ShortcutSignal),
    ShortcutsChanged(ShortcutsChangedSignal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigureShortcutsOutcome {
    Requested,
    Unsupported,
}

#[derive(Debug)]
pub struct PortalClient {
    connection: Connection,
    owner: String,
    proxy: Proxy<'static>,
}

impl PortalClient {
    /// Register this connection with the captured portal peer. This must be called exactly once
    /// for an owner before constructing a client for that owner.
    pub async fn register(
        connection: &Connection,
        owner: &str,
        app_id: &AppID,
    ) -> Result<(), String> {
        let proxy = unique_proxy(connection, owner, PORTAL_PATH, REGISTRY_INTERFACE).await?;
        proxy
            .call::<_, _, ()>("Register", &(app_id, EmptyOptions::default()))
            .await
            .map_err(|error| error.to_string())
    }

    /// Construct the GlobalShortcuts proxy only after registration has succeeded.
    pub async fn new(connection: Connection, owner: String) -> Result<Self, String> {
        let proxy =
            unique_proxy(&connection, &owner, PORTAL_PATH, GLOBAL_SHORTCUTS_INTERFACE).await?;
        // Probe the interface before caching this lazy proxy. The value is not
        // used for capability gating: some implementations expose
        // ConfigureShortcuts while still advertising interface v1.
        proxy
            .get_property::<u32>("version")
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self {
            connection,
            owner,
            proxy,
        })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub async fn create_session(&self) -> Result<PortalSession, String> {
        let handle_token = next_token()?;
        let session_handle_token = next_token()?;
        let request_path = predicted_path(&self.connection, REQUEST_PATH_PREFIX, &handle_token)?;
        let session_path =
            predicted_path(&self.connection, SESSION_PATH_PREFIX, &session_handle_token)?;
        let session =
            PortalSession::new(self.connection.clone(), self.owner.clone(), session_path).await?;
        let mut pending_session = PendingSession::new(session);
        let mut request = PendingRequest::new(&self.connection, &self.owner, request_path).await?;
        let returned_path: OwnedObjectPath = self
            .proxy
            .call(
                "CreateSession",
                &CreateSessionOptions {
                    handle_token,
                    session_handle_token,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        request.verify_path(&returned_path)?;
        let message = request.response().await?;
        let (_, response) = message
            .body()
            .deserialize::<(u32, CreateSessionResponse)>()
            .map_err(|error| format!("Malformed CreateSession response: {error}"))?;
        let expected_session_path = pending_session.path()?;
        if response.session_handle.as_str() != expected_session_path {
            return Err(format!(
                "Portal returned session path {}, expected {expected_session_path}",
                response.session_handle,
            ));
        }
        pending_session.take()
    }

    pub async fn bind_shortcuts(
        &self,
        session: &PortalSession,
        shortcuts: &[NewShortcut],
        parent: Option<&WindowIdentifier>,
    ) -> Result<Vec<BoundShortcut>, String> {
        self.verify_session(session)?;
        let handle_token = next_token()?;
        let request_path = predicted_path(&self.connection, REQUEST_PATH_PREFIX, &handle_token)?;
        let mut request = PendingRequest::new(&self.connection, &self.owner, request_path).await?;
        let parent = parent.map(ToString::to_string).unwrap_or_default();
        let returned_path: OwnedObjectPath = self
            .proxy
            .call(
                "BindShortcuts",
                &(
                    session.path.as_ref(),
                    shortcuts,
                    parent,
                    BindShortcutsOptions { handle_token },
                ),
            )
            .await
            .map_err(|error| error.to_string())?;
        request.verify_path(&returned_path)?;
        let message = request.response().await?;
        let (_, response) = message
            .body()
            .deserialize::<(u32, BindResponse)>()
            .map_err(|error| format!("Malformed BindShortcuts response: {error}"))?;
        Ok(response.shortcuts.into_iter().map(Into::into).collect())
    }

    pub async fn configure_shortcuts(
        &self,
        session: &PortalSession,
        parent: Option<&WindowIdentifier>,
    ) -> Result<ConfigureShortcutsOutcome, String> {
        self.verify_session(session)?;
        let parent = parent.map(ToString::to_string).unwrap_or_default();
        match self
            .proxy
            .call::<_, _, ()>(
                "ConfigureShortcuts",
                &(session.path.as_ref(), parent, EmptyOptions::default()),
            )
            .await
        {
            Ok(()) => Ok(ConfigureShortcutsOutcome::Requested),
            Err(error) if configure_shortcuts_is_unsupported(&error) => {
                Ok(ConfigureShortcutsOutcome::Unsupported)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    pub async fn receive_signals(&self) -> Result<SignalStream<PortalSignal>, String> {
        let stream = self
            .proxy
            .receive_all_signals()
            .await
            .map_err(|error| error.to_string())?;
        Ok(Box::pin(stream.filter_map(|message| {
            std::future::ready(decode_portal_signal(message))
        })))
    }

    fn verify_session(&self, session: &PortalSession) -> Result<(), String> {
        if session.owner == self.owner {
            Ok(())
        } else {
            Err("Shortcut session belongs to a different portal owner".into())
        }
    }
}

fn configure_shortcuts_is_unsupported(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::MethodError(name, _, _) => {
            name.as_str() == "org.freedesktop.DBus.Error.UnknownMethod"
        }
        zbus::Error::FDO(error) => {
            matches!(error.as_ref(), zbus::fdo::Error::UnknownMethod(_))
        }
        _ => false,
    }
}

#[derive(Debug)]
pub struct PortalSession {
    owner: String,
    path: OwnedObjectPath,
    proxy: Proxy<'static>,
}

impl PortalSession {
    async fn new(
        connection: Connection,
        owner: String,
        path: OwnedObjectPath,
    ) -> Result<Self, String> {
        let proxy = unique_proxy(&connection, &owner, path.as_str(), SESSION_INTERFACE).await?;
        Ok(Self { owner, path, proxy })
    }

    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    pub async fn close(&self) -> Result<(), String> {
        self.proxy
            .call::<_, _, ()>("Close", &())
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn receive_closed(&self) -> Result<SignalStream<()>, String> {
        let stream = self
            .proxy
            .receive_signal("Closed")
            .await
            .map_err(|error| error.to_string())?;
        Ok(Box::pin(stream.map(|message| {
            message
                .body()
                .deserialize::<HashMap<String, OwnedValue>>()
                .map(|_| ())
                .map_err(|error| format!("Malformed Closed signal: {error}"))
        })))
    }
}

struct PendingSession {
    session: Option<PortalSession>,
}

impl PendingSession {
    fn new(session: PortalSession) -> Self {
        Self {
            session: Some(session),
        }
    }

    fn path(&self) -> Result<&str, String> {
        self.session
            .as_ref()
            .map(PortalSession::path)
            .ok_or_else(|| "Portal session completed more than once".to_string())
    }

    fn take(&mut self) -> Result<PortalSession, String> {
        self.session
            .take()
            .ok_or_else(|| "Portal session completed more than once".to_string())
    }
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            spawn_close(session.proxy);
        }
    }
}

struct PendingRequest {
    proxy: Proxy<'static>,
    path: OwnedObjectPath,
    responses: Option<ZbusSignalStream<'static>>,
    active: bool,
}

impl PendingRequest {
    async fn new(
        connection: &Connection,
        owner: &str,
        path: OwnedObjectPath,
    ) -> Result<Self, String> {
        let proxy = unique_proxy(connection, owner, path.as_str(), REQUEST_INTERFACE).await?;
        // The match is installed before the portal method can emit a fast Response.
        let responses = proxy
            .receive_signal("Response")
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self {
            proxy,
            path,
            responses: Some(responses),
            active: true,
        })
    }

    fn verify_path(&self, returned: &OwnedObjectPath) -> Result<(), String> {
        if returned == &self.path {
            Ok(())
        } else {
            Err(format!(
                "Portal returned request path {returned}, expected {}",
                self.path
            ))
        }
    }

    async fn response(&mut self) -> Result<zbus::Message, String> {
        let responses = self
            .responses
            .as_mut()
            .ok_or_else(|| "Portal request completed more than once".to_string())?;
        let message = responses
            .next()
            .await
            .ok_or_else(|| "Portal request ended without a Response".to_string())?;
        let (code, _results) = message
            .body()
            .deserialize::<(u32, HashMap<String, OwnedValue>)>()
            .map_err(|error| format!("Malformed portal Response: {error}"))?;
        match classify_response(code)? {
            ResponseClass::Success => {
                self.active = false;
                self.responses = None;
                Ok(message)
            }
            ResponseClass::Cancelled => Err("Portal request was cancelled".into()),
            ResponseClass::Failed => Err("Portal request failed".into()),
        }
    }
}

fn spawn_close(proxy: Proxy<'static>) {
    tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(2), proxy.call::<_, _, ()>("Close", &()))
            .await;
    });
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        spawn_close(self.proxy.clone());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseClass {
    Success,
    Cancelled,
    Failed,
}

fn classify_response(code: u32) -> Result<ResponseClass, String> {
    match code {
        0 => Ok(ResponseClass::Success),
        1 => Ok(ResponseClass::Cancelled),
        2 => Ok(ResponseClass::Failed),
        unknown => Err(format!("Unknown portal response code {unknown}")),
    }
}

async fn unique_proxy(
    connection: &Connection,
    owner: &str,
    path: &str,
    interface: &str,
) -> Result<Proxy<'static>, String> {
    if !owner.starts_with(':') {
        return Err(format!("Portal owner {owner:?} is not a unique D-Bus name"));
    }
    Proxy::new_owned(
        connection.clone(),
        owner.to_string(),
        path.to_string(),
        interface.to_string(),
    )
    .await
    .map_err(|error| error.to_string())
}

fn next_token() -> Result<String, String> {
    let nonce = token_nonce()?;
    let value = NEXT_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "Portal handle token sequence exhausted".to_string())?;
    Ok(token_from_parts(nonce, value))
}

fn token_nonce() -> Result<u128, String> {
    match &*TOKEN_NONCE {
        Ok(nonce) => Ok(*nonce),
        Err(error) => Err(error.clone()),
    }
}
fn token_from_parts(nonce: u128, value: u64) -> String {
    format!("handy_{nonce:032x}_{value}")
}

fn predicted_path(
    connection: &Connection,
    prefix: &str,
    token: &str,
) -> Result<OwnedObjectPath, String> {
    let sender = connection
        .unique_name()
        .ok_or_else(|| "D-Bus connection has no unique name".to_string())?;
    predicted_path_for_sender(sender.as_str(), prefix, token)
}

fn predicted_path_for_sender(
    sender: &str,
    prefix: &str,
    token: &str,
) -> Result<OwnedObjectPath, String> {
    if !sender.starts_with(':') {
        return Err(format!("D-Bus sender {sender:?} is not a unique name"));
    }
    if token.is_empty()
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(format!(
            "Portal handle token {token:?} is not a valid object-path element"
        ));
    }
    let sender = sender[1..].replace('.', "_");
    OwnedObjectPath::try_from(format!("{prefix}/{sender}/{token}"))
        .map_err(|error| format!("Invalid predicted portal object path: {error}"))
}

fn decode_portal_signal(message: zbus::Message) -> Option<Result<PortalSignal, String>> {
    match message.header().member()?.as_str() {
        "Activated" => {
            Some(decode_shortcut_signal(&message, "Activated").map(PortalSignal::Activated))
        }
        "Deactivated" => {
            Some(decode_shortcut_signal(&message, "Deactivated").map(PortalSignal::Deactivated))
        }
        "ShortcutsChanged" => Some(
            message
                .body()
                .deserialize::<(OwnedObjectPath, Vec<WireBoundShortcut>)>()
                .map(|(session_path, shortcuts)| {
                    PortalSignal::ShortcutsChanged(ShortcutsChangedSignal {
                        session_path,
                        shortcuts: shortcuts.into_iter().map(Into::into).collect(),
                    })
                })
                .map_err(|error| format!("Malformed ShortcutsChanged signal: {error}")),
        ),
        _ => None,
    }
}

fn decode_shortcut_signal(
    message: &zbus::Message,
    signal_name: &'static str,
) -> Result<ShortcutSignal, String> {
    let (session_path, shortcut_id, _timestamp, _options) = message
        .body()
        .deserialize::<(OwnedObjectPath, String, u64, HashMap<String, OwnedValue>)>()
        .map_err(|error| format!("Malformed {signal_name} signal: {error}"))?;
    Ok(ShortcutSignal {
        session_path,
        shortcut_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicted_request_and_session_paths_follow_portal_format() {
        assert_eq!(
            predicted_path_for_sender(":1.204", REQUEST_PATH_PREFIX, "handy_17")
                .unwrap()
                .as_str(),
            "/org/freedesktop/portal/desktop/request/1_204/handy_17"
        );
        assert_eq!(
            predicted_path_for_sender(":1.204", SESSION_PATH_PREFIX, "handy_18")
                .unwrap()
                .as_str(),
            "/org/freedesktop/portal/desktop/session/1_204/handy_18"
        );
    }

    #[test]
    fn predicted_paths_reject_non_unique_sender_and_invalid_token() {
        assert!(
            predicted_path_for_sender("org.example.Portal", REQUEST_PATH_PREFIX, "token").is_err()
        );
        assert!(predicted_path_for_sender(":1.2", REQUEST_PATH_PREFIX, "not/valid").is_err());
    }

    #[test]
    fn handle_tokens_are_object_path_safe_and_unique() {
        let first = token_from_parts(0x0123456789abcdef0123456789abcdef, 41);
        let second = token_from_parts(0x0123456789abcdef0123456789abcdef, 42);
        assert_eq!(first, "handy_0123456789abcdef0123456789abcdef_41");
        assert_ne!(first, second);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
        assert!(predicted_path_for_sender(":1.2", REQUEST_PATH_PREFIX, &first).is_ok());
    }

    #[test]
    fn response_codes_are_classified_without_fallback() {
        assert_eq!(classify_response(0).unwrap(), ResponseClass::Success);
        assert_eq!(classify_response(1).unwrap(), ResponseClass::Cancelled);
        assert_eq!(classify_response(2).unwrap(), ResponseClass::Failed);
        assert!(classify_response(3).is_err());
        assert!(classify_response(u32::MAX).is_err());
    }

    #[test]
    fn bound_shortcut_conversion_preserves_authoritative_fields() {
        let shortcut = BoundShortcut::from(WireBoundShortcut(
            "transcribe".into(),
            WireBoundShortcutInfo {
                description: "Transcribe".into(),
                trigger_description: "Ctrl+Space".into(),
            },
        ));
        assert_eq!(shortcut.id, "transcribe");
        assert_eq!(shortcut.description, "Transcribe");
        assert_eq!(shortcut.trigger_description, "Ctrl+Space");
    }

    #[test]
    fn unknown_configure_method_selects_the_v1_fallback() {
        let unsupported = zbus::Error::FDO(Box::new(zbus::fdo::Error::UnknownMethod(
            "ConfigureShortcuts is unavailable".into(),
        )));
        let other = zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
            "configuration failed".into(),
        )));

        assert!(configure_shortcuts_is_unsupported(&unsupported));
        assert!(!configure_shortcuts_is_unsupported(&other));
    }
}
