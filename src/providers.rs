//! Known credential formats. Detection runs locally on the value's shape (and,
//! for formats several services share, on words in the secret's name and
//! notes), so the value never leaves this process just to figure out what it is.

use regex::Regex;
use std::sync::LazyLock;

use crate::db::SecretMeta;
use crate::material::Material;

pub struct Verify {
    pub method: &'static str,
    /// Absolute, or a path (starting with `/`) on the secret's proxy target
    /// for self-hosted services such as n8n or an Atlassian site.
    pub url: &'static str,
    /// Auth spec, see [`crate::proxy::Auth::parse`].
    pub auth: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
    /// (label, JSON pointer) pairs copied from the provider's reply.
    pub facts: &'static [(&'static str, &'static str)],
    /// Response header listing the key's scopes, if the provider sends one.
    pub scope_header: Option<&'static str>,
    /// Some providers answer 200 with `{"ok": false}` for bad keys.
    pub ok_pointer: Option<&'static str>,
    /// Where the reply says when the key expires (RFC 3339 or Unix seconds).
    pub expiry_pointer: Option<&'static str>,
    pub expiry_header: Option<&'static str>,
    /// The provider's own ID for the key, kept for revoking it after rotation.
    pub ref_pointer: Option<&'static str>,
}

const UA: (&str, &str) = ("user-agent", "keys-vault/0.1");

const VERIFY: Verify = Verify {
    method: "GET",
    url: "",
    auth: "bearer",
    headers: &[UA],
    facts: &[],
    scope_header: None,
    ok_pointer: None,
    expiry_pointer: None,
    expiry_header: None,
    ref_pointer: None,
};

/// A part a credential needs besides its main value.
pub struct Need {
    /// `base_url` sets the proxy target; other names become plaintext fields
    /// or, if `secret`, encrypted parts.
    pub name: &'static str,
    pub label: &'static str,
    pub secret: bool,
    pub hint: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// The vault creates the replacement itself through the provider's API,
    /// usually with a managing credential (the secret's parent).
    Auto(&'static str),
    /// Short-lived credentials are created on demand from this one, so
    /// there's nothing to rotate on a schedule.
    Minted(&'static str),
    /// You create the new key on the provider's site and paste it in; the
    /// vault checks it, switches over and tells you when to delete the old one.
    Guided,
    /// Can't be rotated; the reason says what to do instead.
    Never(&'static str),
}

impl Rotation {
    pub fn mode(&self) -> &'static str {
        match self {
            Rotation::Auto(_) => "auto",
            Rotation::Minted(_) => "minted",
            Rotation::Guided => "guided",
            Rotation::Never(_) => "never",
        }
    }
}

pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    /// Value formats that identify the provider on their own.
    pub patterns: &'static [&'static str],
    /// Formats other services share: they count only when a hint matches too.
    pub weak: &'static [&'static str],
    /// Lowercase words in the secret's name or notes that point to this provider.
    pub hints: &'static [&'static str],
    /// Providers whose definite format a hinted match of this one may
    /// override (they share the format). Otherwise a definite format wins
    /// over words in the notes, so notes can't redirect a key elsewhere.
    pub overrides: &'static [&'static str],
    /// api_key, password, private_key or other.
    pub kind: &'static str,
    /// New secrets of this type start out hidden from every token.
    pub owner_only: bool,
    pub summary: &'static str,
    pub risk: &'static str,
    pub risk_reason: &'static str,
    pub docs_url: Option<&'static str>,
    /// The page where you create a replacement (and delete the old key).
    pub rotate_url: Option<&'static str>,
    /// Plain steps for rotating by hand.
    pub steps: &'static [&'static str],
    /// Default proxy target.
    pub api_base: Option<&'static str>,
    pub api_auth: &'static str,
    pub verify: Option<Verify>,
    pub needs: &'static [Need],
    pub rotation: Rotation,
    /// Suggested rotation schedule.
    pub rotate_days: Option<u32>,
    /// The provider of the managing credential that rotation or minting uses.
    pub parent_provider: Option<&'static str>,
    /// What that managing credential is, in words.
    pub parent_hint: Option<&'static str>,
}

const BASE: Provider = Provider {
    id: "",
    name: "",
    patterns: &[],
    weak: &[],
    hints: &[],
    overrides: &[],
    kind: "api_key",
    owner_only: false,
    summary: "",
    risk: "medium",
    risk_reason: "",
    docs_url: None,
    rotate_url: None,
    steps: &[],
    api_base: None,
    api_auth: "bearer",
    verify: None,
    needs: &[],
    rotation: Rotation::Guided,
    rotate_days: None,
    parent_provider: None,
    parent_hint: None,
};

const NEW_KEY_STEPS: &[&str] = &[
    "Open the provider's key page (link below) and create a new key with the same permissions.",
    "Paste the new key here. The vault checks it works and switches every app over.",
    "Delete the old key on the same page.",
];

// Order matters: more specific formats come first.
pub static PROVIDERS: &[Provider] = &[
    Provider {
        id: "anthropic-admin",
        name: "Anthropic Admin API key",
        patterns: &[r"^sk-ant-admin01-[A-Za-z0-9_\-]{20,}$"],
        summary: "Manages an Anthropic organization: members, workspaces, API keys, usage and cost reports.",
        risk: "high",
        risk_reason: "Can disable API keys and manage members for the whole organization.",
        docs_url: Some("https://docs.claude.com/en/api/administration-api"),
        rotate_url: Some("https://platform.claude.com/settings/admin-keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.anthropic.com"),
        api_auth: "header:x-api-key",
        verify: Some(Verify {
            url: "https://api.anthropic.com/v1/organizations/me",
            auth: "header:x-api-key",
            headers: &[("anthropic-version", "2023-06-01"), UA],
            facts: &[("organization", "/name"), ("organization_id", "/id")],
            ..VERIFY
        }),
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "anthropic",
        name: "Anthropic (Claude) API key",
        patterns: &[r"^sk-ant-api\d\d-[A-Za-z0-9_\-]{20,}$"],
        summary: "Calls the Claude API (Messages, Batches, Files, Models). Usage is billed to the key's workspace.",
        risk: "high",
        risk_reason: "Every request spends money on the owning account.",
        docs_url: Some("https://docs.claude.com/en/api/overview"),
        rotate_url: Some("https://platform.claude.com/settings/keys"),
        steps: &[
            "Open the Claude Console key page (link below) and click Create Key, in the same workspace.",
            "Paste the new key here. The vault checks it works and switches every app over.",
            "If an Anthropic Admin key is set as this key's manager, the vault disables the old key for you after the overlap. Otherwise disable or delete it on the same page.",
        ],
        api_base: Some("https://api.anthropic.com"),
        api_auth: "header:x-api-key",
        verify: Some(Verify {
            url: "https://api.anthropic.com/v1/models?limit=1",
            auth: "header:x-api-key",
            headers: &[("anthropic-version", "2023-06-01"), UA],
            ..VERIFY
        }),
        rotation: Rotation::Guided,
        rotate_days: Some(90),
        parent_provider: Some("anthropic-admin"),
        parent_hint: Some("an Anthropic Admin API key (optional: lets the vault disable the old key)"),
        ..BASE
    },
    Provider {
        id: "openrouter-management",
        name: "OpenRouter management key",
        weak: &[r"^sk-or-v1-[A-Za-z0-9]{32,}$"],
        hints: &["management", "provisioning", "mgmt"],
        overrides: &["openrouter"],
        summary: "Creates, lists, limits and deletes the account's OpenRouter API keys. It can't call models itself.",
        risk: "high",
        risk_reason: "Can create keys that spend the account's credits, and delete the keys your apps use.",
        docs_url: Some("https://openrouter.ai/docs/guides/overview/auth/management-api-keys"),
        rotate_url: Some("https://openrouter.ai/settings/management-keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://openrouter.ai/api"),
        verify: Some(Verify {
            url: "https://openrouter.ai/api/v1/key",
            facts: &[("label", "/data/label"), ("is_management_key", "/data/is_management_key")],
            ..VERIFY
        }),
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "openrouter",
        name: "OpenRouter API key",
        patterns: &[r"^sk-or-v1-[A-Za-z0-9]{32,}$"],
        summary: "Calls many hosted LLMs through OpenRouter's OpenAI-compatible API, billed to the account's credits.",
        risk: "high",
        risk_reason: "Spends account credits on every request.",
        docs_url: Some("https://openrouter.ai/docs"),
        rotate_url: Some("https://openrouter.ai/settings/keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://openrouter.ai/api"),
        verify: Some(Verify {
            url: "https://openrouter.ai/api/v1/key",
            facts: &[("label", "/data/label"), ("credit_limit", "/data/limit"), ("usage", "/data/usage")],
            expiry_pointer: Some("/data/expires_at"),
            ..VERIFY
        }),
        rotation: Rotation::Auto("openrouter"),
        rotate_days: Some(90),
        parent_provider: Some("openrouter-management"),
        parent_hint: Some("an OpenRouter management key"),
        ..BASE
    },
    Provider {
        id: "openai",
        name: "OpenAI API key",
        patterns: &[r"^sk-(proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}$", r"^sk-[A-Za-z0-9]{40,}$"],
        summary: "Calls the OpenAI API (models, embeddings, files, assistants). Usage is billed to the key's project.",
        risk: "high",
        risk_reason: "Every request spends money on the owning project.",
        docs_url: Some("https://platform.openai.com/docs/api-reference"),
        rotate_url: Some("https://platform.openai.com/api-keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.openai.com"),
        verify: Some(Verify {
            url: "https://api.openai.com/v1/models",
            ..VERIFY
        }),
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "github-app",
        name: "GitHub App private key",
        weak: &[r"-----BEGIN (RSA )?PRIVATE KEY-----"],
        hints: &["github app", "gh app", "github-app"],
        overrides: &["private-key"],
        kind: "private_key",
        summary: "Signs in as a GitHub App. The vault turns it into installation tokens that expire after an hour, so apps never hold a long-lived GitHub credential.",
        risk: "high",
        risk_reason: "Has whatever repository permissions the App was granted on its installations.",
        docs_url: Some(
            "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation",
        ),
        rotate_url: Some("https://github.com/settings/apps"),
        steps: &[
            "Open your GitHub App's settings (link below), scroll to Private keys and click Generate a private key.",
            "Paste the downloaded .pem file's contents here.",
            "Delete the old private key on the same page.",
        ],
        api_base: Some("https://api.github.com"),
        needs: &[
            Need {
                name: "app_id",
                label: "App ID",
                secret: false,
                hint: "Shown at the top of the App's settings page.",
            },
            Need {
                name: "installation_id",
                label: "Installation ID",
                secret: false,
                hint: "The number at the end of the installation's settings URL.",
            },
        ],
        rotation: Rotation::Minted("github-app"),
        rotate_days: Some(365),
        ..BASE
    },
    Provider {
        id: "github",
        name: "GitHub token",
        patterns: &[r"^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}$", r"^github_pat_[A-Za-z0-9_]{40,}$"],
        summary: "Acts as a GitHub user or app against the GitHub API: repositories, issues, pull requests, Actions.",
        risk: "high",
        risk_reason: "Can usually push code or change repository settings, depending on its scopes.",
        docs_url: Some("https://docs.github.com/en/rest"),
        rotate_url: Some("https://github.com/settings/personal-access-tokens/new"),
        steps: &[
            "Open the link below and generate a fine-grained token limited to the repositories this one is used for, with an expiry. Prefer that over a classic token.",
            "Paste the new token here. The vault checks it works and switches every app over.",
            "Delete the old token at github.com/settings/tokens (classic) or github.com/settings/personal-access-tokens. For automation, a GitHub App is better: its tokens expire every hour.",
        ],
        api_base: Some("https://api.github.com"),
        verify: Some(Verify {
            url: "https://api.github.com/user",
            headers: &[
                ("accept", "application/vnd.github+json"),
                ("x-github-api-version", "2022-11-28"),
                UA,
            ],
            facts: &[("login", "/login"), ("name", "/name")],
            scope_header: Some("x-oauth-scopes"),
            expiry_header: Some("github-authentication-token-expiration"),
            ..VERIFY
        }),
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "gitlab",
        name: "GitLab personal access token",
        patterns: &[r"^glpat-[A-Za-z0-9_\-]{20,}$"],
        summary: "Acts as a GitLab user against the GitLab API.",
        risk: "high",
        risk_reason: "Can usually read and write repositories, depending on its scopes.",
        docs_url: Some("https://docs.gitlab.com/api/rest/"),
        rotate_url: Some("https://gitlab.com/-/user_settings/personal_access_tokens"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://gitlab.com/api/v4"),
        api_auth: "header:private-token",
        verify: Some(Verify {
            url: "https://gitlab.com/api/v4/personal_access_tokens/self",
            auth: "header:private-token",
            facts: &[("token_name", "/name"), ("scopes", "/scopes")],
            expiry_pointer: Some("/expires_at"),
            ref_pointer: Some("/id"),
            ..VERIFY
        }),
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "stripe-live",
        name: "Stripe live-mode key",
        patterns: &[r"^(sk|rk)_live_[A-Za-z0-9]{20,}$"],
        summary: "Calls the Stripe API in live mode: real charges, refunds, customers and payouts.",
        risk: "high",
        risk_reason: "Moves real money.",
        docs_url: Some("https://docs.stripe.com/api"),
        rotate_url: Some("https://dashboard.stripe.com/apikeys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.stripe.com"),
        verify: Some(Verify {
            url: "https://api.stripe.com/v1/account",
            facts: &[
                ("account_id", "/id"),
                ("display_name", "/settings/dashboard/display_name"),
                ("country", "/country"),
            ],
            ..VERIFY
        }),
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "stripe-test",
        name: "Stripe test-mode key",
        patterns: &[r"^(sk|rk)_test_[A-Za-z0-9]{20,}$"],
        summary: "Calls the Stripe API in test mode. No real money moves.",
        risk: "low",
        risk_reason: "Test mode only.",
        docs_url: Some("https://docs.stripe.com/api"),
        rotate_url: Some("https://dashboard.stripe.com/test/apikeys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.stripe.com"),
        verify: Some(Verify {
            url: "https://api.stripe.com/v1/account",
            facts: &[("account_id", "/id"), ("display_name", "/settings/dashboard/display_name")],
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "slack-refresh",
        name: "Slack refresh token (token rotation)",
        patterns: &[r"^xoxe-1-[A-Za-z0-9\-]{20,}$"],
        summary: "A Slack app's refresh token. The vault exchanges it for bot tokens that expire every 12 hours.",
        risk: "medium",
        risk_reason: "Can keep issuing tokens for the app's bot until the app is reinstalled.",
        docs_url: Some("https://docs.slack.dev/authentication/using-token-rotation"),
        rotate_url: Some("https://api.slack.com/apps"),
        steps: &[
            "Open your Slack app (link below), go to OAuth & Permissions and reinstall the app to your workspace.",
            "Paste the new refresh token here.",
        ],
        api_base: Some("https://slack.com/api"),
        needs: &[
            Need {
                name: "client_id",
                label: "Client ID",
                secret: false,
                hint: "Basic Information → App Credentials.",
            },
            Need {
                name: "client_secret",
                label: "Client secret",
                secret: true,
                hint: "Basic Information → App Credentials.",
            },
        ],
        rotation: Rotation::Minted("slack"),
        ..BASE
    },
    Provider {
        id: "slack",
        name: "Slack token",
        patterns: &[r"^xox[abpr]-[A-Za-z0-9\-]{10,}$", r"^xoxe\.xox[bp]-[A-Za-z0-9\-]{10,}$"],
        summary: "Acts as a Slack bot or user in a workspace: reading and posting messages, depending on scopes.",
        risk: "medium",
        risk_reason: "Can read or post in the workspace within its scopes.",
        docs_url: Some("https://api.slack.com/web"),
        rotate_url: Some("https://api.slack.com/apps"),
        steps: &[
            "Open your Slack app (link below) → OAuth & Permissions.",
            "Either turn on token rotation (then store the refresh token here instead: it renews itself), or revoke all tokens and reinstall the app to get a new one.",
            "Paste the new token here.",
        ],
        api_base: Some("https://slack.com/api"),
        verify: Some(Verify {
            method: "POST",
            url: "https://slack.com/api/auth.test",
            facts: &[("team", "/team"), ("user", "/user"), ("url", "/url")],
            scope_header: Some("x-oauth-scopes"),
            ok_pointer: Some("/ok"),
            ..VERIFY
        }),
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "huggingface",
        name: "Hugging Face token",
        patterns: &[r"^hf_[A-Za-z0-9]{30,}$"],
        summary: "Accesses Hugging Face models, datasets and Spaces, and the Inference API.",
        risk: "medium",
        risk_reason: "Write-role tokens can push to repositories; read tokens can access private models.",
        docs_url: Some("https://huggingface.co/docs/hub/api"),
        rotate_url: Some("https://huggingface.co/settings/tokens"),
        steps: &[
            "Open the link below. Next to the token, choose Invalidate and refresh (or create a new fine-grained token).",
            "Paste the new token here.",
        ],
        api_base: Some("https://huggingface.co"),
        verify: Some(Verify {
            url: "https://huggingface.co/api/whoami-v2",
            facts: &[
                ("user", "/name"),
                ("token_role", "/auth/accessToken/role"),
                ("token_name", "/auth/accessToken/displayName"),
            ],
            ..VERIFY
        }),
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "groq",
        name: "Groq API key",
        patterns: &[r"^gsk_[A-Za-z0-9]{40,}$"],
        summary: "Calls Groq's hosted LLM inference API (OpenAI-compatible).",
        risk: "medium",
        risk_reason: "Spends account usage on every request.",
        docs_url: Some("https://console.groq.com/docs"),
        rotate_url: Some("https://console.groq.com/keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.groq.com"),
        verify: Some(Verify {
            url: "https://api.groq.com/openai/v1/models",
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "xai",
        name: "xAI API key",
        patterns: &[r"^xai-[A-Za-z0-9]{40,}$"],
        summary: "Calls xAI's Grok models API.",
        risk: "high",
        risk_reason: "Spends money on every request.",
        docs_url: Some("https://docs.x.ai/docs"),
        rotate_url: Some("https://console.x.ai"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.x.ai"),
        verify: Some(Verify {
            url: "https://api.x.ai/v1/api-key",
            facts: &[("key_name", "/name"), ("permissions", "/acls")],
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "sendgrid",
        name: "SendGrid API key",
        patterns: &[r"^SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}$"],
        summary: "Sends email through SendGrid and manages the account's email settings.",
        risk: "high",
        risk_reason: "Can send email as your domain, which is a phishing risk if leaked.",
        docs_url: Some("https://www.twilio.com/docs/sendgrid/api-reference"),
        rotate_url: Some("https://app.sendgrid.com/settings/api_keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.sendgrid.com"),
        verify: Some(Verify {
            url: "https://api.sendgrid.com/v3/scopes",
            facts: &[("scopes", "/scopes")],
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "digitalocean",
        name: "DigitalOcean API token",
        patterns: &[r"^dop_v1_[a-f0-9]{64}$"],
        summary: "Manages DigitalOcean infrastructure: droplets, databases, DNS, storage.",
        risk: "high",
        risk_reason: "Can create, destroy and bill infrastructure.",
        docs_url: Some("https://docs.digitalocean.com/reference/api/"),
        rotate_url: Some("https://cloud.digitalocean.com/account/api/tokens"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.digitalocean.com"),
        verify: Some(Verify {
            url: "https://api.digitalocean.com/v2/account",
            facts: &[("email", "/account/email"), ("status", "/account/status")],
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "npm",
        name: "npm access token",
        patterns: &[r"^npm_[A-Za-z0-9]{36}$"],
        summary: "Authenticates to the npm registry; publish tokens can release new package versions.",
        risk: "high",
        risk_reason: "A leaked publish token is a supply-chain attack on everyone who installs your packages.",
        docs_url: Some("https://docs.npmjs.com/about-access-tokens"),
        rotate_url: Some("https://www.npmjs.com/settings/~/tokens"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://registry.npmjs.org"),
        verify: Some(Verify {
            url: "https://registry.npmjs.org/-/whoami",
            facts: &[("username", "/username")],
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "replicate",
        name: "Replicate API token",
        patterns: &[r"^r8_[A-Za-z0-9]{30,}$"],
        summary: "Runs models on Replicate, billed per second of compute.",
        risk: "medium",
        risk_reason: "Spends money on every prediction.",
        docs_url: Some("https://replicate.com/docs/reference/http"),
        rotate_url: Some("https://replicate.com/account/api-tokens"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.replicate.com"),
        verify: Some(Verify {
            url: "https://api.replicate.com/v1/account",
            facts: &[("username", "/username"), ("account_type", "/type")],
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "tailscale-oauth",
        name: "Tailscale OAuth client",
        patterns: &[r"^tskey-client-[A-Za-z0-9]+-[A-Za-z0-9]+$"],
        summary: "A Tailscale OAuth client secret. The vault uses it to get hour-long API tokens, and to create auth keys when rotating them.",
        risk: "high",
        risk_reason: "Can add devices to, or reconfigure, the network this vault relies on, within its scopes.",
        docs_url: Some("https://tailscale.com/kb/1215/oauth-clients"),
        rotate_url: Some("https://console.tailscale.com/admin/settings/trust-credentials"),
        steps: &[
            "Open the link below and create a new OAuth client with the same scopes and tags.",
            "Paste the new client secret here (and its client ID).",
            "Revoke the old client on the same page.",
        ],
        api_base: Some("https://api.tailscale.com"),
        needs: &[Need {
            name: "client_id",
            label: "Client ID",
            secret: false,
            hint: "Shown when you create the OAuth client.",
        }],
        rotation: Rotation::Minted("tailscale"),
        rotate_days: Some(365),
        ..BASE
    },
    Provider {
        id: "tailscale-authkey",
        name: "Tailscale auth key",
        patterns: &[r"^tskey-auth-[A-Za-z0-9]+-[A-Za-z0-9]+$"],
        summary: "Adds a device to your tailnet. Once the device has joined, the key isn't needed again.",
        risk: "high",
        risk_reason: "Anyone holding it can join a device to the network this vault trusts.",
        docs_url: Some("https://tailscale.com/kb/1085/auth-keys"),
        rotate_url: Some("https://console.tailscale.com/admin/settings/keys"),
        steps: &[
            "If the device it was for has already joined, just revoke this key on the page below and delete it here.",
            "Otherwise generate a new auth key there (tagged, single-use, short expiry) and paste it here.",
        ],
        rotation: Rotation::Auto("tailscale-authkey"),
        rotate_days: Some(30),
        parent_provider: Some("tailscale-oauth"),
        parent_hint: Some("a Tailscale OAuth client with the auth_keys scope and a tag"),
        ..BASE
    },
    Provider {
        id: "tailscale",
        name: "Tailscale API key",
        patterns: &[r"^tskey-(api|scim|webhook)-[A-Za-z0-9]+-[A-Za-z0-9]+$"],
        summary: "Manages your tailnet through the Tailscale API: devices, ACLs, keys and DNS.",
        risk: "high",
        risk_reason: "Can reconfigure the network this vault relies on.",
        docs_url: Some("https://tailscale.com/kb/1101/api"),
        rotate_url: Some("https://console.tailscale.com/admin/settings/keys"),
        steps: &[
            "Better: replace this with an OAuth client (Settings → Trust credentials), which the vault can renew on its own.",
            "Or generate a new API key on the page below, paste it here and revoke the old one.",
        ],
        api_base: Some("https://api.tailscale.com"),
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "linear",
        name: "Linear API key",
        patterns: &[r"^lin_api_[A-Za-z0-9]{30,}$"],
        summary: "Reads and writes Linear issues, projects and comments as the key's user.",
        risk: "medium",
        risk_reason: "Can read and change your issue tracker.",
        docs_url: Some("https://linear.app/developers"),
        rotate_url: Some("https://linear.app/settings/account/security"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.linear.app"),
        api_auth: "header:authorization",
        ..BASE
    },
    Provider {
        id: "google",
        name: "Google API key",
        patterns: &[r"^AIza[0-9A-Za-z_\-]{35}$"],
        summary: "Google Cloud / Gemini API key. What it can call depends on the restrictions set in Google Cloud.",
        risk: "medium",
        risk_reason: "Unrestricted keys can run up bills on any enabled Google API.",
        docs_url: Some("https://cloud.google.com/docs/authentication/api-keys"),
        rotate_url: Some("https://console.cloud.google.com/apis/credentials"),
        steps: &[
            "Open Credentials (link below), click the key and choose Rotate key. Google makes a copy with the same restrictions.",
            "Paste the new key here.",
            "Back on that page, choose Delete the previous key once your apps work (it can be undeleted for 30 days).",
        ],
        api_base: Some("https://generativelanguage.googleapis.com"),
        api_auth: "header:x-goog-api-key",
        rotation: Rotation::Auto("google-apikey"),
        rotate_days: Some(90),
        parent_provider: Some("google-service-account"),
        parent_hint: Some("a Google service account key with the API Keys Admin role on the key's project"),
        ..BASE
    },
    Provider {
        id: "google-service-account",
        name: "Google service account key",
        patterns: &[r#""type"\s*:\s*"service_account""#],
        kind: "private_key",
        summary: "A Google Cloud service account's JSON key. Acts as that service account with whatever IAM roles it holds.",
        risk: "high",
        risk_reason: "Long-lived and usable from anywhere; its reach depends on its IAM roles.",
        docs_url: Some("https://cloud.google.com/iam/docs/service-account-creds"),
        rotate_url: Some("https://console.cloud.google.com/iam-admin/serviceaccounts"),
        steps: &[
            "Open Service accounts (link below), pick the account → Keys → Add key → JSON.",
            "Paste the downloaded file's contents here.",
            "Delete the old key on the same tab.",
        ],
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "google-oauth-client",
        name: "Google OAuth client secret",
        patterns: &[r"^GOCSPX-[A-Za-z0-9_\-]{20,}$"],
        summary: "The secret half of a Google OAuth client, used by an app to sign users in with Google or act on their behalf.",
        risk: "medium",
        risk_reason: "Lets someone impersonate your app in Google's sign-in flow.",
        docs_url: Some("https://support.google.com/cloud/answer/15549257"),
        rotate_url: Some("https://console.cloud.google.com/auth/clients"),
        steps: &[
            "Open Clients (link below), click this client and choose Add secret (a client can have two at once).",
            "Paste the new secret here and update the app that uses it.",
            "Once the app works with the new secret, disable and delete the old one there.",
        ],
        needs: &[Need {
            name: "client_id",
            label: "Client ID",
            secret: false,
            hint: "Ends in .apps.googleusercontent.com.",
        }],
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "azure-app-secret",
        name: "Microsoft Entra (Azure) client secret",
        patterns: &[r"^[A-Za-z0-9_~.\-]{3}\dQ~[A-Za-z0-9_~.\-]{30,36}$"],
        summary: "A Microsoft Entra app registration's client secret, used by an app (such as an Azure Bot) to get tokens as itself.",
        risk: "high",
        risk_reason: "Acts as the app with all the permissions it was granted.",
        docs_url: Some("https://learn.microsoft.com/en-us/graph/api/application-addpassword"),
        rotate_url: Some("https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"),
        steps: &[
            "Open App registrations (link below) → your app → Certificates & secrets → New client secret. Pick 12 months or less.",
            "Paste the new secret's Value here (not its ID).",
            "Delete the old secret on the same page once the app works.",
        ],
        needs: &[
            Need {
                name: "tenant_id",
                label: "Tenant (directory) ID",
                secret: false,
                hint: "App registration → Overview.",
            },
            Need {
                name: "client_id",
                label: "Application (client) ID",
                secret: false,
                hint: "App registration → Overview.",
            },
        ],
        rotation: Rotation::Auto("azure-app-secret"),
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "cloudflare",
        name: "Cloudflare API token",
        patterns: &[r"^cf(ut|at)_[A-Za-z0-9_\-]{40,}$"],
        weak: &[r"^[A-Za-z0-9_\-]{40}$"],
        hints: &["cloudflare", "cloud flare"],
        summary: "Calls the Cloudflare API with the permissions chosen when the token was made (for example, editing one domain's DNS).",
        risk: "high",
        risk_reason: "DNS control lets someone redirect your domain or get certificates for it.",
        docs_url: Some("https://developers.cloudflare.com/fundamentals/api/"),
        rotate_url: Some("https://dash.cloudflare.com/profile/api-tokens"),
        steps: &[
            "Open API Tokens (link below). Click … next to the token → Roll → Confirm. You get a new value with the same permissions.",
            "Paste the new value here. The old value stops working immediately.",
        ],
        api_base: Some("https://api.cloudflare.com/client/v4"),
        verify: Some(Verify {
            url: "https://api.cloudflare.com/client/v4/user/tokens/verify",
            facts: &[("token_status", "/result/status")],
            ok_pointer: Some("/success"),
            expiry_pointer: Some("/result/expires_on"),
            ref_pointer: Some("/result/id"),
            ..VERIFY
        }),
        rotation: Rotation::Auto("cloudflare"),
        rotate_days: Some(90),
        parent_provider: Some("cloudflare"),
        parent_hint: Some("a Cloudflare token with the \"API Tokens: Edit\" permission"),
        ..BASE
    },
    Provider {
        id: "atlassian",
        name: "Atlassian API token",
        patterns: &[r"^ATATT[A-Za-z0-9_\-=]{20,}$"],
        weak: &[r"^[A-Za-z0-9_\-=]{24,}$"],
        hints: &["atlassian", "jira", "confluence"],
        summary: "Signs in to Atlassian Cloud (Jira, Confluence) as your user, with your permissions.",
        risk: "high",
        risk_reason: "Can read and change everything your Atlassian account can.",
        docs_url: Some("https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/"),
        rotate_url: Some("https://id.atlassian.com/manage-profile/security/api-tokens"),
        steps: &[
            "Open API tokens (link below) and create a new token. Pick the shortest expiry you're comfortable with (at most a year).",
            "Paste it here.",
            "Revoke the old token on the same page.",
        ],
        api_auth: "basic:email",
        verify: Some(Verify {
            url: "/rest/api/3/myself",
            auth: "basic:email",
            facts: &[
                ("account", "/displayName"),
                ("email", "/emailAddress"),
                ("account_id", "/accountId"),
            ],
            ..VERIFY
        }),
        needs: &[
            Need {
                name: "email",
                label: "Atlassian account email",
                secret: false,
                hint: "The email you sign in to Atlassian with.",
            },
            Need {
                name: "base_url",
                label: "Site URL",
                secret: false,
                hint: "e.g. https://yourteam.atlassian.net",
            },
        ],
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "elevenlabs",
        name: "ElevenLabs API key",
        patterns: &[r"^sk_[a-f0-9]{48}$"],
        summary: "Generates speech, voices and sound with ElevenLabs, billed to the account's credits.",
        risk: "medium",
        risk_reason: "Spends account credits.",
        docs_url: Some("https://elevenlabs.io/docs/api-reference/authentication"),
        rotate_url: Some("https://elevenlabs.io/app/settings/api-keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.elevenlabs.io"),
        api_auth: "header:xi-api-key",
        verify: Some(Verify {
            url: "https://api.elevenlabs.io/v1/user",
            auth: "header:xi-api-key",
            facts: &[
                ("tier", "/subscription/tier"),
                ("characters_used", "/subscription/character_count"),
                ("character_limit", "/subscription/character_limit"),
            ],
            ..VERIFY
        }),
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "tavily",
        name: "Tavily API key",
        patterns: &[r"^tvly-[A-Za-z0-9_\-]{20,}$"],
        summary: "Web search and extraction for AI agents through Tavily, billed per credit.",
        risk: "low",
        risk_reason: "Only spends search credits.",
        docs_url: Some("https://docs.tavily.com/documentation/api-reference/introduction"),
        rotate_url: Some("https://app.tavily.com/home"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.tavily.com"),
        verify: Some(Verify {
            url: "https://api.tavily.com/usage",
            facts: &[
                ("key_usage", "/key/usage"),
                ("key_limit", "/key/limit"),
                ("plan", "/account/current_plan"),
            ],
            ..VERIFY
        }),
        rotate_days: Some(365),
        ..BASE
    },
    Provider {
        id: "n8n",
        name: "n8n API key",
        weak: &[
            r"^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$",
            r"^n8n_api_[A-Za-z0-9]{20,}$",
        ],
        hints: &["n8n"],
        overrides: &["jwt"],
        summary: "Manages workflows, executions and credentials on your n8n server through its public API.",
        risk: "high",
        risk_reason: "Can change automations that may hold other credentials.",
        docs_url: Some("https://docs.n8n.io/api/authentication/"),
        rotate_url: None,
        steps: &[
            "In n8n, open Settings → n8n API and create a new API key.",
            "Paste it here.",
            "Delete the old key on the same page.",
        ],
        api_auth: "header:x-n8n-api-key",
        verify: Some(Verify {
            url: "/api/v1/workflows?limit=1",
            auth: "header:x-n8n-api-key",
            ..VERIFY
        }),
        needs: &[Need {
            name: "base_url",
            label: "n8n address",
            secret: false,
            hint: "e.g. https://n8n.example.com",
        }],
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "unifi",
        name: "UniFi Site Manager API key",
        weak: &[r"^[A-Za-z0-9_\-]{32}$"],
        hints: &["unifi", "ubiquiti", "ubnt"],
        summary: "Reads your UniFi sites, devices and hosts through Ubiquiti's Site Manager API.",
        risk: "medium",
        risk_reason: "Exposes your network inventory; write access may follow as the API grows.",
        docs_url: Some("https://developer.ui.com/site-manager-api/gettingstarted"),
        rotate_url: Some("https://unifi.ui.com/settings/api-keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.ui.com"),
        api_auth: "header:x-api-key",
        verify: Some(Verify {
            url: "https://api.ui.com/v1/hosts?pageSize=1",
            auth: "header:x-api-key",
            ..VERIFY
        }),
        rotate_days: Some(365),
        ..BASE
    },
    Provider {
        id: "alpaca-live",
        name: "Alpaca live trading key",
        weak: &[r"^[A-Za-z0-9]{30,64}$"],
        hints: &["alpaca"],
        summary: "Places real trades and reads balances in an Alpaca brokerage account.",
        risk: "high",
        risk_reason: "Trades with real money.",
        docs_url: Some("https://docs.alpaca.markets/docs/authentication"),
        rotate_url: Some("https://app.alpaca.markets"),
        steps: &[
            "Open the Alpaca dashboard (link below), make sure the live account is selected, then API Keys → Regenerate.",
            "Paste the new secret here and the new key ID in the Key ID field. The old pair stops working at once.",
        ],
        api_base: Some("https://api.alpaca.markets"),
        api_auth: "headers:APCA-API-KEY-ID={key_id};APCA-API-SECRET-KEY={value}",
        verify: Some(Verify {
            url: "https://api.alpaca.markets/v2/account",
            auth: "headers:APCA-API-KEY-ID={key_id};APCA-API-SECRET-KEY={value}",
            facts: &[("account", "/account_number"), ("status", "/status"), ("currency", "/currency")],
            ..VERIFY
        }),
        needs: &[Need {
            name: "key_id",
            label: "Key ID",
            secret: false,
            hint: "Starts with AK for live accounts.",
        }],
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "alpaca-paper",
        name: "Alpaca paper trading key",
        weak: &[r"^[A-Za-z0-9]{30,64}$"],
        hints: &["alpaca"],
        summary: "Places simulated trades in an Alpaca paper account. No real money moves.",
        risk: "low",
        risk_reason: "Paper trading only.",
        docs_url: Some("https://docs.alpaca.markets/docs/paper-trading"),
        rotate_url: Some("https://app.alpaca.markets"),
        steps: &[
            "Open the Alpaca dashboard (link below), switch to the paper account (top left), then API Keys → Regenerate.",
            "Paste the new secret here and the new key ID in the Key ID field. The old pair stops working at once.",
        ],
        api_base: Some("https://paper-api.alpaca.markets"),
        api_auth: "headers:APCA-API-KEY-ID={key_id};APCA-API-SECRET-KEY={value}",
        verify: Some(Verify {
            url: "https://paper-api.alpaca.markets/v2/account",
            auth: "headers:APCA-API-KEY-ID={key_id};APCA-API-SECRET-KEY={value}",
            facts: &[("account", "/account_number"), ("status", "/status")],
            ..VERIFY
        }),
        needs: &[Need {
            name: "key_id",
            label: "Key ID",
            secret: false,
            hint: "Starts with PK for paper accounts.",
        }],
        ..BASE
    },
    Provider {
        id: "alphavantage",
        name: "Alpha Vantage API key",
        weak: &[r"^[A-Z0-9]{16}$"],
        hints: &["alpha vantage", "alphavantage", "alpha"],
        summary: "Reads stock, forex and crypto market data from Alpha Vantage.",
        risk: "low",
        risk_reason: "Read-only market data; the worst case is someone using up your quota.",
        docs_url: Some("https://www.alphavantage.co/documentation/"),
        rotate_url: Some("https://www.alphavantage.co/support/#api-key"),
        steps: &[
            "Alpha Vantage has no key management page: claim a new free key with the form at the link below.",
            "Paste it here. You can't delete the old key yourself; it just goes unused (or ask their support to disable it).",
        ],
        api_base: Some("https://www.alphavantage.co"),
        api_auth: "query:apikey",
        ..BASE
    },
    Provider {
        id: "finnhub",
        name: "Finnhub API key",
        weak: &[r"^[A-Za-z0-9]{20,64}$"],
        hints: &["finnhub"],
        summary: "Reads stock prices, fundamentals and news from Finnhub.",
        risk: "low",
        risk_reason: "Read-only market data.",
        docs_url: Some("https://finnhub.io/docs/api/authentication"),
        rotate_url: Some("https://finnhub.io/dashboard"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://finnhub.io/api/v1"),
        api_auth: "header:x-finnhub-token",
        verify: Some(Verify {
            url: "https://finnhub.io/api/v1/stock/market-status?exchange=US",
            auth: "header:x-finnhub-token",
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "twelvedata",
        name: "Twelve Data API key",
        weak: &[r"^[a-f0-9]{32}$"],
        hints: &["twelve data", "twelvedata", "12data"],
        summary: "Reads stock, forex and crypto prices from Twelve Data.",
        risk: "low",
        risk_reason: "Read-only market data.",
        docs_url: Some("https://twelvedata.com/docs#authentication"),
        rotate_url: Some("https://twelvedata.com/account/api-keys"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://api.twelvedata.com"),
        api_auth: "headers:Authorization=apikey {value}",
        verify: Some(Verify {
            url: "https://api.twelvedata.com/api_usage",
            auth: "headers:Authorization=apikey {value}",
            facts: &[
                ("plan", "/plan_category"),
                ("usage", "/current_usage"),
                ("plan_limit", "/plan_limit"),
            ],
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "fmp",
        name: "Financial Modeling Prep API key",
        weak: &[r"^[A-Za-z0-9]{32}$"],
        hints: &["fmp", "financial modeling", "financialmodelingprep"],
        summary: "Reads company financials, prices and filings from Financial Modeling Prep.",
        risk: "low",
        risk_reason: "Read-only market data.",
        docs_url: Some("https://site.financialmodelingprep.com/developer/docs"),
        rotate_url: Some("https://site.financialmodelingprep.com/developer/docs/dashboard"),
        steps: NEW_KEY_STEPS,
        api_base: Some("https://financialmodelingprep.com"),
        api_auth: "query:apikey",
        verify: Some(Verify {
            url: "https://financialmodelingprep.com/stable/quote-short?symbol=AAPL",
            auth: "query:apikey",
            ..VERIFY
        }),
        ..BASE
    },
    Provider {
        id: "magic-21st",
        name: "21st.dev API key",
        weak: &[r"^[a-f0-9]{64}$", r"^[A-Za-z0-9_\-]{20,}$"],
        hints: &["magic", "21st"],
        summary: "Lets the 21st.dev MCP server (formerly Magic) generate UI components for your coding agent. 21st.dev reset all keys from the old Magic console, so a key from there no longer works.",
        risk: "low",
        risk_reason: "Spends the account's generation quota.",
        docs_url: Some("https://21st.dev/mcp"),
        rotate_url: Some("https://21st.dev/mcp"),
        steps: &[
            "Open 21st.dev/mcp (link below) and generate a new key. Keys from the old Magic console were all reset and no longer work.",
            "Paste it here. Apps read it as API_KEY_21ST.",
        ],
        api_base: Some("https://21st.dev/api"),
        api_auth: "header:x-api-key",
        ..BASE
    },
    Provider {
        id: "google-stitch",
        name: "Google Stitch API key",
        weak: &[r"^\S{20,}$"],
        hints: &["stitch"],
        summary: "Lets tools use Google Stitch, Google's AI UI-design service, on your account (through its MCP endpoint).",
        risk: "low",
        risk_reason: "Uses your Stitch quota.",
        docs_url: Some("https://stitch.withgoogle.com"),
        rotate_url: Some("https://stitch.withgoogle.com/settings"),
        steps: &[
            "Open Stitch (link below) → your profile menu → Stitch settings → API key → Create key.",
            "Paste it here, then delete the old key there.",
        ],
        api_base: Some("https://stitch.googleapis.com"),
        api_auth: "header:x-goog-api-key",
        ..BASE
    },
    Provider {
        id: "apns",
        name: "Apple push notification key (.p8)",
        weak: &[r"-----BEGIN PRIVATE KEY-----"],
        hints: &["apns", "apple", "push notification"],
        overrides: &["private-key"],
        kind: "private_key",
        summary: "Signs Apple Push Notification service requests, so a server can send notifications to your apps.",
        risk: "medium",
        risk_reason: "Lets someone send push notifications to your app's users.",
        docs_url: Some("https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns"),
        rotate_url: Some("https://developer.apple.com/account/resources/authkeys/list"),
        steps: &[
            "Open Keys (link below), click +, tick Apple Push Notifications service and download the new .p8 file.",
            "Paste the file's contents here, and update the Key ID field.",
            "Once your server works with it, revoke the old key there.",
        ],
        needs: &[
            Need {
                name: "key_id",
                label: "Key ID",
                secret: false,
                hint: "10 characters, shown next to the key.",
            },
            Need {
                name: "team_id",
                label: "Team ID",
                secret: false,
                hint: "Top right of the developer portal.",
            },
        ],
        rotate_days: Some(365),
        ..BASE
    },
    Provider {
        id: "aws",
        name: "AWS access key ID",
        patterns: &[r"^(AKIA|ASIA)[A-Z0-9]{16}$"],
        summary: "AWS access key ID. Useless alone; paired with its secret access key it can do whatever the IAM user or role allows.",
        risk: "high",
        risk_reason: "IAM credentials often have broad, billable access.",
        docs_url: Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"),
        rotate_url: Some("https://console.aws.amazon.com/iam/home#/security_credentials"),
        steps: NEW_KEY_STEPS,
        rotate_days: Some(90),
        ..BASE
    },
    Provider {
        id: "crypto-wallet",
        name: "Crypto wallet private key",
        patterns: &[r"^0x[0-9a-fA-F]{64}$"],
        kind: "private_key",
        owner_only: true,
        summary: "The private key of an Ethereum-style wallet. Whoever has it controls the wallet's funds.",
        risk: "high",
        risk_reason: "Anyone who reads it can empty the wallet, and transfers can't be reversed.",
        rotation: Rotation::Never(
            "A wallet key can't be changed. If it may have leaked, create a new wallet (ideally on a hardware wallet) and move the funds to it.",
        ),
        ..BASE
    },
    Provider {
        id: "private-key",
        name: "Private key (PEM)",
        patterns: &[r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----"],
        kind: "private_key",
        owner_only: true,
        summary: "A private key: SSH, TLS, code signing or PGP. Whoever holds it can impersonate its owner.",
        risk: "high",
        risk_reason: "Private keys can't be scoped; anyone holding one has full use of it.",
        steps: &[
            "Generate a new key pair where this one is used (for SSH: ssh-keygen -t ed25519).",
            "Install the new public key, paste the new private key here, then remove the old public key everywhere.",
        ],
        ..BASE
    },
    Provider {
        id: "jwt",
        name: "JSON Web Token",
        patterns: &[r"^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$"],
        summary: "A signed JSON Web Token. Its issuer and expiry are shown in the facts.",
        risk: "medium",
        risk_reason: "Grants whatever the issuer allows until it expires.",
        steps: &["Issue a new token where this one came from and paste it here."],
        ..BASE
    },
    Provider {
        id: "hostinger",
        name: "Hostinger VPS root password",
        weak: &[r"(?s)^.{1,}$"],
        hints: &["hostinger"],
        kind: "password",
        owner_only: true,
        summary: "The root password of a Hostinger VPS: full control of that server.",
        risk: "high",
        risk_reason: "Root on a public server; if it leaks, the whole server is someone else's.",
        docs_url: Some("https://www.hostinger.com/support/8942826-how-to-change-your-vps-ssh-password-at-hostinger/"),
        rotate_url: Some("https://hpanel.hostinger.com/vps"),
        steps: &[
            "Open hPanel → VPS (link below) → your server → Settings → Root password, set a new long random one and save.",
            "Better: under Settings → SSH keys add your public key, then turn off password login for root on the server.",
            "Paste the new password here.",
        ],
        rotate_days: Some(180),
        ..BASE
    },
    Provider {
        id: "password",
        name: "Password",
        weak: &[r"(?s)^.{1,}$"],
        hints: &["password", "passwd", "pwd", "passphrase", "login", "account", "root"],
        kind: "password",
        owner_only: true,
        summary: "A password for an account or server. Only you can see it; no token can read it.",
        risk: "high",
        risk_reason: "Passwords usually unlock a whole account.",
        steps: &[
            "Change the password on the site or server it belongs to. Use a long random one, and turn on two-factor sign-in if you can.",
            "Paste the new password here.",
        ],
        ..BASE
    },
];

static COMPILED: LazyLock<Vec<(usize, bool, Regex)>> = LazyLock::new(|| {
    PROVIDERS
        .iter()
        .enumerate()
        .flat_map(|(i, p)| {
            let strong = p.patterns.iter().map(move |pat| (i, true, *pat));
            let weak = p.weak.iter().map(move |pat| (i, false, *pat));
            strong.chain(weak)
        })
        .map(|(i, strong, pat)| (i, strong, Regex::new(pat).expect("valid provider regex")))
        .collect()
});

fn hinted(p: &Provider, label: &str) -> bool {
    p.hints.iter().any(|h| label.contains(h))
}

/// Works out the provider from the value's format, using `label` (the
/// secret's name and notes) to choose between services that share a format.
pub fn detect(value: &str, label: &str) -> Option<&'static Provider> {
    let v = value.trim();
    let label = label.to_lowercase().replace(['_', '-'], " ");
    let mut strong: Vec<&'static Provider> = vec![];
    let mut weak: Vec<&'static Provider> = vec![];
    for (i, is_strong, re) in COMPILED.iter() {
        let p = &PROVIDERS[*i];
        if !re.is_match(v) {
            continue;
        }
        if *is_strong {
            if !strong.iter().any(|x| x.id == p.id) {
                strong.push(p);
            }
        } else if hinted(p, &label) && !weak.iter().any(|x| x.id == p.id) {
            weak.push(p);
        }
    }
    weak.retain(|w| !strong.iter().any(|s| s.id == w.id));
    // A hinted shared format wins only over the providers it's allowed to
    // override; "password" fits anything, so it's the last resort.
    let (passwords, weak): (Vec<_>, Vec<_>) = weak.into_iter().partition(|p| p.kind == "password");
    weak.iter()
        .find(|w| strong.iter().all(|s| w.overrides.contains(&s.id)))
        .or_else(|| strong.iter().find(|s| hinted(s, &label)))
        .or_else(|| strong.first())
        .or_else(|| passwords.first())
        .copied()
}

/// Settles details the value alone can't show, such as whether an Alpaca
/// key is for paper or live trading (its key ID says).
pub fn refine(p: &'static Provider, fields: &serde_json::Value) -> &'static Provider {
    let key_id = fields.get("key_id").and_then(serde_json::Value::as_str).unwrap_or("");
    match p.id {
        "alpaca-live" | "alpaca-paper" if key_id.starts_with("PK") => by_id("alpaca-paper").unwrap_or(p),
        "alpaca-live" | "alpaca-paper" if key_id.starts_with("AK") => by_id("alpaca-live").unwrap_or(p),
        _ => p,
    }
}

pub fn by_id(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.id == id)
}

/// The provider of a stored secret: the owner's choice if set, else detected.
pub fn resolve(meta: &SecretMeta, value: &str) -> Option<&'static Provider> {
    let p = meta
        .provider_hint
        .as_deref()
        .and_then(by_id)
        .or_else(|| detect(value, &format!("{} {}", meta.name, meta.notes)))?;
    Some(refine(p, &meta.fields))
}

/// Labels of the parts this provider needs that the secret doesn't have yet.
pub fn missing(p: &Provider, meta: &SecretMeta, m: &Material) -> Vec<&'static str> {
    p.needs
        .iter()
        .filter(|n| match n.name {
            "base_url" => meta.proxy_base_url.is_none(),
            name if n.secret => m.get(name).is_none_or(str::is_empty),
            name => meta.fields.get(name).and_then(serde_json::Value::as_str).is_none_or(str::is_empty),
        })
        .map(|n| n.label)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test PEM blocks, assembled at runtime so secret scanners don't flag them.
    fn pem(kind: &str) -> String {
        format!("{}{kind} PRIVATE KEY-----\nabc", "-----BEGIN ")
    }

    fn id(v: &str) -> Option<&'static str> {
        detect(v, "").map(|p| p.id)
    }
    fn idl(v: &str, label: &str) -> Option<&'static str> {
        detect(v, label).map(|p| p.id)
    }

    #[test]
    fn detects_common_formats() {
        let x = "a".repeat(48);
        assert_eq!(id(&format!("sk-ant-api03-{x}")), Some("anthropic"));
        assert_eq!(id(&format!("sk-ant-admin01-{x}")), Some("anthropic-admin"));
        assert_eq!(id(&format!("sk-or-v1-{}", "0".repeat(64))), Some("openrouter"));
        assert_eq!(id(&format!("sk-proj-{x}")), Some("openai"));
        assert_eq!(id(&format!("ghp_{}", "A".repeat(36))), Some("github"));
        assert_eq!(id(&format!("github_pat_{}", "A".repeat(82))), Some("github"));
        assert_eq!(id(&format!("sk_live_{}", "A".repeat(24))), Some("stripe-live"));
        assert_eq!(id(&format!("rk_test_{}", "A".repeat(24))), Some("stripe-test"));
        assert_eq!(id(&format!("AKIA{}", "Q".repeat(16))), Some("aws"));
        assert_eq!(id(&pem("OPENSSH")), Some("private-key"));
        assert_eq!(id("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"), Some("jwt"));
        assert_eq!(
            id(&format!("tskey-auth-k{}-{}", "a".repeat(10), "b".repeat(30))),
            Some("tailscale-authkey")
        );
        assert_eq!(
            id(&format!("tskey-client-k{}-{}", "a".repeat(10), "b".repeat(30))),
            Some("tailscale-oauth")
        );
        assert_eq!(id(&format!("ATATT3x{}", "F".repeat(180))), Some("atlassian"));
        assert_eq!(id(&format!("sk_{}", "a1".repeat(24))), Some("elevenlabs"));
        assert_eq!(id(&format!("tvly-dev-{}", "Z".repeat(30))), Some("tavily"));
        assert_eq!(id(&format!("GOCSPX-{}", "x".repeat(28))), Some("google-oauth-client"));
        assert_eq!(id(&format!("abc8Q~{}", "y".repeat(34))), Some("azure-app-secret"));
        assert_eq!(id(&format!("0x{}", "ab".repeat(32))), Some("crypto-wallet"));
        assert_eq!(id(&format!("xoxe-1-{}", "M".repeat(40))), Some("slack-refresh"));
        assert_eq!(
            id(&serde_json::json!({ "type": (["service", "account"].join("_")), "project_id": "p" }).to_string()),
            Some("google-service-account")
        );
        assert_eq!(id("just some password"), None);
    }

    #[test]
    fn labels_pick_between_shared_formats() {
        let or = format!("sk-or-v1-{}", "0".repeat(64));
        assert_eq!(idl(&or, "Openrouter Management Key"), Some("openrouter-management"));
        assert_eq!(idl(&or, "chatbot key"), Some("openrouter"));
        assert_eq!(idl(&"Q".repeat(16), "Alpha vantage market data api key"), Some("alphavantage"));
        assert_eq!(idl(&"Q".repeat(16), "something else"), None, "a bare 16-character code is anyone's");
        assert_eq!(idl(&"0f".repeat(16), "Twelve Data API Key"), Some("twelvedata"));
        assert_eq!(idl(&"Ab1".repeat(11)[..32], "UNIFI_API_KEY"), Some("unifi"));
        assert_eq!(idl(&"Ab_".repeat(14)[..40], "Cloud flare dns"), Some("cloudflare"));
        assert_eq!(idl("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "N8N API KEY"), Some("n8n"));
        assert_eq!(idl("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "session"), Some("jwt"));
        assert_eq!(idl("hunter2 is weak", "hostinger vps login"), Some("hostinger"));
        assert_eq!(idl("hunter2 is weak", "Bank login"), Some("password"));
        assert_eq!(
            id(&format!("cfut_{}", "A".repeat(44))),
            Some("cloudflare"),
            "new Cloudflare tokens need no hint"
        );
        assert_eq!(
            idl(&format!("ghp_{}", "A".repeat(36)), "my account token"),
            Some("github"),
            "a real format beats the password hint"
        );
        let aiza = format!("AIza{}", "x".repeat(35));
        assert_eq!(
            idl(&aiza, "for the magic jira n8n stitch thing"),
            Some("google"),
            "notes can't move a key to another provider"
        );
        let ts = format!("tskey-auth-k{}-{}", "a".repeat(10), "b".repeat(30));
        assert_eq!(idl(&ts, "jira"), Some("tailscale-authkey"));
        assert_eq!(idl(&pem("").replace("BEGIN  ", "BEGIN "), "Apple APNS key"), Some("apns"));
        assert_eq!(idl(&pem("RSA"), "GitHub App key"), Some("github-app"));
        let p = detect(&"S".repeat(44), "Alpaca secret").unwrap();
        assert_eq!(refine(p, &serde_json::json!({ "key_id": "PKABC" })).id, "alpaca-paper");
        assert_eq!(refine(p, &serde_json::json!({ "key_id": "AKABC" })).id, "alpaca-live");
    }

    #[test]
    fn every_provider_is_well_formed() {
        let mut ids = std::collections::HashSet::new();
        for p in PROVIDERS {
            assert!(ids.insert(p.id), "duplicate id {}", p.id);
            assert!(crate::proxy::Auth::parse(p.api_auth).is_some(), "{}", p.id);
            assert!(!p.summary.is_empty() && !p.risk_reason.is_empty(), "{}", p.id);
            assert!(["low", "medium", "high"].contains(&p.risk), "{}", p.id);
            assert!(["api_key", "password", "private_key", "other"].contains(&p.kind), "{}", p.id);
            assert!(
                p.weak.is_empty() || !p.hints.is_empty(),
                "{} has hint-only formats but no hints",
                p.id
            );
            for o in p.overrides {
                assert!(by_id(o).is_some(), "{}: unknown override {o}", p.id);
            }
            assert!(!p.patterns.is_empty() || !p.weak.is_empty(), "{} has no formats", p.id);
            if let Some(v) = &p.verify {
                assert!(crate::proxy::Auth::parse(v.auth).is_some(), "{}", p.id);
                assert!(v.url.starts_with("https://") || v.url.starts_with('/'), "{}", p.id);
                if v.url.starts_with('/') {
                    assert!(
                        p.needs.iter().any(|n| n.name == "base_url"),
                        "{}: relative verify URL needs a base_url",
                        p.id
                    );
                }
            }
            for u in [p.docs_url, p.rotate_url, p.api_base].into_iter().flatten() {
                assert!(u.starts_with("https://"), "{}", p.id);
            }
            if matches!(p.rotation, Rotation::Guided) {
                assert!(!p.steps.is_empty(), "{} has guided rotation but no steps", p.id);
            }
            for n in p.needs {
                assert!(
                    n.name == "base_url" || crate::material::valid_part_name(n.name),
                    "{}: {}",
                    p.id,
                    n.name
                );
            }
            if let Some(pp) = p.parent_provider {
                assert!(by_id(pp).is_some(), "{}: unknown parent provider {pp}", p.id);
            }
        }
    }
}
