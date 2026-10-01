//! A scripted backend (§3.1, tests): returns queued replies in order and
//! records the digest of every request it was sent.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Instant;

use harness_core::{Digest, Source, Untrusted};

use crate::profile::Profile;
use crate::wire::{render_request, request_digest};
use crate::{
    Completion, EndpointClass, FinishReason, ModelBackend, ModelError, ModelIdentity, ModelRequest,
    RawToolCall,
};

/// Queued replies, in order.
#[derive(Debug)]
pub struct ScriptedBackend {
    profile: Profile,
    replies: RefCell<VecDeque<Result<Completion, ModelError>>>,
    seen: RefCell<Vec<Digest>>,
}

impl ScriptedBackend {
    /// A backend that will answer with `replies`, in order.
    pub fn new(profile: Profile, replies: Vec<Result<Completion, ModelError>>) -> Self {
        Self {
            profile,
            replies: RefCell::new(replies.into()),
            seen: RefCell::new(Vec::new()),
        }
    }

    /// Digests of the rendered requests received so far.
    pub fn seen(&self) -> Vec<Digest> {
        self.seen.borrow().clone()
    }
}

/// A plain text reply finishing with `stop`.
pub fn text_reply(content: &str) -> Completion {
    Completion {
        content: Untrusted::new(content.to_owned(), Source::Model),
        tool_calls: Vec::new(),
        finish: FinishReason::Stop,
        usage: None,
        request_bytes: 0,
        reply_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
        retried: Vec::new(),
    }
}

/// A native tool-call reply.
pub fn tool_reply(name: &str, arguments: &str) -> Completion {
    Completion {
        content: Untrusted::new(String::new(), Source::Model),
        tool_calls: vec![Untrusted::new(
            RawToolCall {
                name: name.to_owned(),
                arguments: arguments.to_owned(),
            },
            Source::Model,
        )],
        finish: FinishReason::ToolCalls,
        usage: None,
        request_bytes: 0,
        reply_bytes: u64::try_from(name.len() + arguments.len()).unwrap_or(u64::MAX),
        retried: Vec::new(),
    }
}

impl ModelBackend for ScriptedBackend {
    fn identity(&self) -> ModelIdentity {
        ModelIdentity {
            endpoint: EndpointClass::Scripted,
            profile_id: self.profile.id().to_owned(),
            profile_sha256: self.profile.sha256().map(|d| d.to_string()),
            profile_validated: self.profile.validated(),
            profile_stamp_sha256: self.profile.stamp_sha256().map(str::to_owned),
            api_key_handle: None,
            claimed: crate::ServerClaims::default(),
        }
    }

    fn complete(&self, req: &ModelRequest, _deadline: Instant) -> Result<Completion, ModelError> {
        let rendered =
            render_request(req, &self.profile).map_err(|e| ModelError::Unusable(e.to_string()))?;
        self.seen.borrow_mut().push(request_digest(&rendered));
        self.replies
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(ModelError::Unusable("script exhausted".into())))
    }
}
