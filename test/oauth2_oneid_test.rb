# frozen_string_literal: true

require 'minitest/autorun'
require 'rack/test'
require 'rack/session'
require 'webmock/minitest'
require 'stringio'
require 'logger'
require 'omniauth-oauth2-oneid'

# Integration-style tests: the full OmniAuth request/callback cycle runs through Rack,
# with OneID and the GitLab API stubbed by WebMock (no network needed).
OmniAuth.config.request_validation_phase = nil
OmniAuth.config.allowed_request_methods = %i[get post]
OmniAuth.config.on_failure = ->(env) { [401, {}, [env['omniauth.error.type'].to_s]] }

class OneIDStrategyTest < Minitest::Test
  include Rack::Test::Methods

  JSON_H = { 'Content-Type' => 'application/json' }.freeze
  BIZ = '1234567890123456'
  GL = 'https://gitlab.example.com'

  def setup
    @opts = { businesses: [BIZ] }
    @log = StringIO.new
    OmniAuth.config.logger = Logger.new(@log)
    stub_request(:post, 'https://one.th/oauth/token')
      .to_return(status: 200, headers: JSON_H,
                 body: { access_token: 'AT', token_type: 'Bearer', expires_in: 900, refresh_token: 'RT' }.to_json)
    account(id: '9001', account_category: 'Residential')
    businesses([{ id: BIZ, status: 'Active' }])
    departments([])
  end

  def app
    opts = @opts
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 's' * 64
      use OmniAuth::Builder do
        provider :oauth2_oneid, 'cid', 'csecret', opts
      end
      run lambda { |env|
        auth = env['omniauth.auth']
        [200, { 'content-type' => 'application/json' }, [auth.to_hash.to_json]]
      }
    end.to_app
  end

  def account(**data)
    stub_request(:get, 'https://one.th/go-api/v1/citizen/service/account?q=all')
      .to_return(status: 200, headers: JSON_H, body: { data: data }.to_json)
  end

  def businesses(list)
    stub_request(:get, 'https://one.th/api/v3/business/service/list-business')
      .to_return(status: 200, headers: JSON_H, body: { result: 'Success', data: list }.to_json)
  end

  def departments(lists)
    stub_request(:get, 'https://one.th/go-api/v1/business/service/account-detail')
      .to_return(status: 200, headers: JSON_H, body: { data: { business_lists: lists } }.to_json)
  end

  def login(state: :valid)
    get '/auth/oauth2_oneid'
    assert_equal 302, last_response.status
    real = Rack::Utils.parse_query(URI(last_response['Location']).query)['state']
    refute_empty real.to_s
    q = { code: 'CODE' }
    q[:state] = real if state == :valid
    q[:state] = 'forged' if state == :forged
    get '/auth/oauth2_oneid/callback', q
    last_response
  end

  def auth = JSON.parse(last_response.body)

  def enable_block(api: GL)
    @opts[:auto_block] = { enabled: true, gitlab_api: api, gitlab_token: 'GLTOKEN' }
  end

  def gitlab_users(users)
    stub_request(:get, %r{\A#{GL}/api/v4/users\?})
      .with(headers: { 'PRIVATE-TOKEN' => 'GLTOKEN' })
      .to_return(status: 200, headers: JSON_H, body: users.to_json)
  end

  # --- state / CSRF ---
  def test_allowed_login_succeeds
    assert_equal 200, login.status
    assert_equal '9001', auth['uid']
    assert_equal [BIZ], auth['extra']['business_ids']
    refute auth['extra'].key?('id_info'), 'raw PII must be opt-in'
    assert_includes [true, false], auth['info']['email_verified']
  end

  def test_missing_state_is_rejected
    assert_equal 'csrf_detected', login(state: :none).body
  end

  def test_forged_state_is_rejected
    assert_equal 'csrf_detected', login(state: :forged).body
  end

  # --- business gate ---
  def test_business_not_in_allowlist_is_forbidden
    businesses([{ id: '999', status: 'Active' }])
    assert_equal 'forbidden', login.body
  end

  def test_inactive_business_does_not_grant_access
    businesses([{ id: BIZ, status: 'Suspended' }])
    assert_equal 'forbidden', login.body
  end

  def test_active_check_can_be_turned_off
    @opts[:require_active_business] = false
    businesses([{ id: BIZ, status: 'Suspended' }])
    assert_equal 200, login.status
  end

  def test_status_compare_is_case_insensitive
    businesses([{ id: BIZ, status: 'active' }])
    assert_equal 200, login.status
  end

  def test_skip_info_cannot_bypass_gate
    @opts[:skip_info] = true
    businesses([{ id: '999', status: 'Active' }])
    assert_equal 'forbidden', login.body
  end

  def test_numeric_config_ids_match_string_ids
    @opts[:businesses] = [BIZ.to_i]
    assert_equal 200, login.status
  end

  def test_no_business_is_denied_when_required
    @opts[:businesses] = []
    businesses([])
    assert_equal 'forbidden', login.body
  end

  def test_no_allowlist_any_active_business_passes
    @opts[:businesses] = []
    businesses([{ id: '42', status: 'Active' }])
    assert_equal 200, login.status
  end

  # --- departments ---
  def test_department_match
    @opts[:departments] = { BIZ => ['D1'] }
    departments([{ id: BIZ, account_roles: [{ dept_id: 'D0' }, { dept_id: 'D1' }] }])
    assert_equal 200, login.status
  end

  def test_department_mismatch
    @opts[:departments] = { BIZ => ['D9'] }
    departments([{ id: BIZ, account_roles: [{ dept_id: 'D1' }] }])
    assert_equal 'forbidden', login.body
  end

  def test_department_info_fetched_once
    @opts[:departments] = { BIZ => ['D1'] }
    @opts[:include_raw_info] = true
    departments([{ id: BIZ, account_roles: [{ dept_id: 'D1' }] }])
    assert_equal 200, login.status
    assert_requested :get, 'https://one.th/go-api/v1/business/service/account-detail', times: 1
    assert auth['extra'].key?('department_info')
  end

  # --- invalid responses fail closed without auto block ---
  def test_missing_account_id_is_invalid_and_not_blocked
    enable_block
    account(first_name_th: 'x')
    assert_equal 'invalid_response', login.body
    assert_not_requested :any, %r{gitlab}
  end

  def test_null_business_list_is_invalid_and_not_blocked
    enable_block
    stub_request(:get, 'https://one.th/api/v3/business/service/list-business')
      .to_return(status: 200, headers: JSON_H, body: { result: 'Fail', data: nil }.to_json)
    assert_equal 'invalid_response', login.body
    assert_not_requested :any, %r{gitlab}
  end

  def test_missing_status_is_invalid_and_not_blocked
    enable_block
    businesses([{ id: BIZ }])
    assert_equal 'invalid_response', login.body
    assert_not_requested :any, %r{gitlab}
  end

  def test_missing_status_ok_when_active_check_off
    @opts[:require_active_business] = false
    businesses([{ id: BIZ }])
    assert_equal 200, login.status
  end

  # --- auto block ---
  def test_auto_block_blocks_exact_identity_only
    enable_block
    businesses([{ id: '999', status: 'Active' }])
    gitlab_users([{ id: 7, state: 'active', identities: [{ provider: 'oauth2_oneid', extern_uid: '9001' }] }])
    block = stub_request(:post, "#{GL}/api/v4/users/7/block").to_return(status: 201, body: 'true')
    assert_equal 'forbidden', login.body
    assert_requested block
  end

  def test_auto_block_skips_user_with_other_identity
    enable_block
    businesses([{ id: '999', status: 'Active' }])
    gitlab_users([{ id: 1, state: 'active', identities: [{ provider: 'oauth2_oneid', extern_uid: 'someone-else' }] }])
    assert_equal 'forbidden', login.body
    assert_not_requested :post, %r{/block}
  end

  def test_auto_block_refuses_plain_http_remote_host
    enable_block(api: 'http://gitlab.example.com')
    businesses([{ id: '999', status: 'Active' }])
    assert_equal 'forbidden', login.body
    assert_not_requested :any, %r{gitlab\.example\.com}
    assert_match(/must use https/, @log.string)
  end

  def test_gitlab_error_body_not_logged
    enable_block
    businesses([{ id: '999', status: 'Active' }])
    stub_request(:get, %r{\A#{GL}/api/v4/users\?}).to_return(status: 500, body: 'SECRET-BODY')
    assert_equal 'forbidden', login.body
    refute_match(/SECRET-BODY/, @log.string)
    refute_match(/GLTOKEN/, @log.string)
  end

  # --- info ---
  def test_residential_uses_thai_name
    account(id: '1', account_category: 'Residential', account_title_th: 'นาย', first_name_th: 'สมชาย',
            last_name_th: 'ใจดี', first_name_eng: 'Somchai', last_name_eng: 'Jaidee', thai_email: 'a@thai.com')
    login
    assert_equal 'นายสมชาย ใจดี', auth['info']['name']
    assert_equal 'a@thai.com', auth['info']['email']
    assert_equal true, auth['info']['email_verified']
  end

  def test_non_residential_uses_english_name
    account(id: '1', account_category: 'Juristic', account_title_eng: 'Mr.', first_name_eng: 'Somchai',
            last_name_eng: 'Jaidee', first_name_th: 'สมชาย')
    login
    assert_equal 'Mr. Somchai Jaidee', auth['info']['name']
    assert_equal false, auth['info']['email_verified']
  end

  def test_non_residential_without_english_falls_back_to_thai
    account(id: '1', account_category: 'Juristic', first_name_th: 'สมชาย', last_name_th: 'ใจดี')
    login
    assert_equal 'สมชาย ใจดี', auth['info']['name']
  end

  def test_nothing_printed_to_stdout
    out, = capture_io { login }
    assert_empty out
  end
end
