# Omniauth::Strategies::OAuth2OneID

OmniAuth strategy for OneID (https://one.th) with an optional business / department allowlist.

## Usage

```ruby
provider :oauth2_oneid, ENV['ONEID_CLIENT_ID'], ENV['ONEID_CLIENT_SECRET'],
  businesses: ["1234567890123456"],          # allowed OneID business ids (strings)
  departments: { "1234567890123456" => ["<dept id>"] }  # optional, replaces `businesses` when set
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `businesses` | `[]` | Allowed business ids. Empty = any business. Write ids as strings. |
| `departments` | `{}` | `{ business_id => [dept_id, ...] }`. When set, only this check is used. |
| `require_business` | `true` | Deny accounts that belong to no business. |
| `require_active_business` | `true` | Count only businesses whose `status` is `Active`. An entry with no `status` fails the login with `invalid_response`. |
| `include_raw_info` | `false` | Put the full OneID account / business / department responses in `extra`. They contain personal data. |
| `auto_block` | disabled | Block the matching GitLab user when the gate denies a login. See below. |

A denied login goes to OmniAuth's failure endpoint with `forbidden`. A OneID response that cannot be
read (no account id, no business list) fails with `invalid_response` and never triggers auto block.

### auto_block

```ruby
auto_block: {
  enabled: true,
  gitlab_api: "https://gitlab.example.com",  # https required; plain http only for localhost
  gitlab_token: ENV['GITLAB_ADMIN_TOKEN'],
  open_timeout: 5,
  timeout: 10
}
```

Only a GitLab user whose identity matches this provider and the OneID account id exactly is blocked.

## Development

```bash
bundle install
bundle exec rake test    # full request/callback cycle, OneID and GitLab API stubbed (no network)
bundle exec rake audit   # check dependencies against the Ruby advisory database
```

## Security notes

- The OAuth `state` parameter is verified on callback (CSRF protection). Versions before 0.3.0 turned
  this off with `provider_ignores_state: true`. Do not set it back unless OneID stops returning `state`.
- Pin the callback URL so it is not built from the request's `Host` header (CVE-2026-63183): set
  `client_options: { redirect_uri: "https://your.app/auth/oauth2_oneid/callback" }`, or the strategy's
  `full_host` option, or `OmniAuth.config.allowed_hosts` (omniauth >= 2.2.0 only warns until one is set).
- The allowlist is checked on login only. A member removed from a business keeps existing sessions
  and tokens in the consuming app until they expire or are revoked there.
