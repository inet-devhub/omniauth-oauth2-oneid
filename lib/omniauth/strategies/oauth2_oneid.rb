# frozen_string_literal: true

require 'omniauth-oauth2'
require 'faraday'
require 'json'
require 'set'
require 'uri'

module OmniAuth
  module Strategies
    ConnectionError = Class.new(Faraday::ConnectionFailed)
    TimeoutError = Class.new(Faraday::TimeoutError)

    class OAuth2OneID < OmniAuth::Strategies::OAuth2
      # The account is valid but not allowed in by the business/department gate.
      ForbiddenError = Class.new(StandardError)
      # OneID answered with something we cannot use (missing id, missing data list).
      # Never treated as "not a member", so it never triggers auto block.
      InvalidResponseError = Class.new(StandardError)

      LOOPBACK_HOSTS = %w[localhost 127.0.0.1 ::1].freeze

      option :name, "oauth2_oneid"
      option :client_options,
      {
        site: "https://one.th",
        user_info_url: "/go-api/v1/citizen/service/account?q=all",
        auth_scheme: :request_body,
        authorize_url: "/api/oauth/getcode",
        token_url: "/oauth/token",
        business_url: "/api/v3/business/service/list-business",
        department_url: "/go-api/v1/business/service/account-detail"
      }
      # Allowlist of OneID business ids. Empty = any business.
      option :businesses, []
      # { "<business id>" => ["<dept id>", ...] }. When set, it replaces the business allowlist.
      option :departments, {}
      # Deny accounts that belong to no business at all.
      option :require_business, true
      # Count only businesses whose status is "Active".
      option :require_active_business, true
      # Put the full OneID account, business and department responses in extra.
      # They contain personal data (citizen id, phone, address), so it is off by default.
      option :include_raw_info, false
      option :auto_block,
      {
        enabled: false,
        gitlab_api: "http://localhost",
        gitlab_token: "",
        open_timeout: 5,
        timeout: 10
      }

      uid do
        user_path['id'].to_s.strip
      end

      info do
        {
          name: display_name,
          email: email,
          # thai_email is a mailbox issued by OneID itself.
          email_verified: !email.to_s.strip.empty?,
          urls: {
            oneid: "https://one.th/portal_index"
          }
        }
      end

      extra do
        hash = { business_ids: active_businesses.map { |b| normalize_id(b['id']) } }
        if options.include_raw_info
          hash[:id_info] = user_path
          hash[:business_info] = business_info
          hash[:department_info] = department_info unless options.departments.empty?
        end
        hash
      end

      def email
        user_path['thai_email']
      end

      def raw_info
        @raw_info ||= access_token.get(options.client_options[:user_info_url]).parsed
      end

      def business_info
        @business_info ||= access_token.get(options.client_options[:business_url]).parsed
      end

      def department_info
        @department_info ||= access_token.get(options.client_options[:department_url]).parsed
      end

      def authorize_params
        params = super
        params.transform_values { |v| v.respond_to?(:call) ? v.call(request) : v }
      end

      def callback_url
        options.client_options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def callback_phase
        super
      rescue ForbiddenError => e
        fail!(:forbidden, e)
      rescue InvalidResponseError => e
        fail!(:invalid_response, e)
      end

      # The gate runs here rather than in `info`, so `skip_info` cannot bypass it.
      def auth_hash
        authorize_account!
        super
      end

      protected

        def build_access_token
          verifier = request.params["code"]
          client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
        end

        def user_path
          data = raw_info.is_a?(Hash) ? raw_info['data'] : nil
          raise InvalidResponseError, "OneID account response has no data" unless data.is_a?(Hash)

          data
        end

        def display_name
          thai = "#{field('account_title_th')}#{field('first_name_th')} #{field('last_name_th')}".strip
          return thai if field('account_category') == "Residential"

          english = [field('account_title_eng'), field('first_name_eng'), field('last_name_eng')].reject(&:empty?).join(' ')
          english.empty? ? thai : english
        end

        def field(key)
          user_path[key].to_s.strip
        end

        def authorize_account!
          raise InvalidResponseError, "OneID account has no id" if uid.empty?
          return if account_allowed?

          log :info, "Access denied for OneID account #{uid}"
          gitlab_auto_block
          raise ForbiddenError, "Forbidden. Unauthorized access restricted."
        end

        def account_allowed?
          return false if options.require_business && active_businesses.empty?
          return department_allowed? unless options.departments.empty?
          return true if options.businesses.empty?

          allowed = normalize_ids(options.businesses)
          active_businesses.any? { |b| allowed.include?(normalize_id(b['id'])) }
        end

        def active_businesses
          @active_businesses ||= begin
            data = business_info.is_a?(Hash) ? business_info['data'] : nil
            raise InvalidResponseError, "OneID list-business response has no data list" unless data.is_a?(Array)

            list = data.select { |b| b.is_a?(Hash) }
            if options.require_active_business
              # A missing status means the response is not what we expect, not that the
              # business is inactive: deny without auto block instead of blocking everyone.
              if list.any? { |b| !b.key?('status') }
                raise InvalidResponseError, "OneID list-business entry has no status (set require_active_business: false to skip this check)"
              end

              list = list.select { |b| b['status'].to_s.strip.casecmp?("active") }
            end
            list
          end
        end

        def department_allowed?
          allowed = allowed_departments
          department_lists.any? do |b|
            b_id = normalize_id(b['id'])
            depts = allowed[b_id]
            next false unless depts

            Array(b['account_roles']).any? do |role|
              next false unless role.is_a?(Hash)

              dept_id = normalize_id(role['dept_id'])
              if depts.include?(dept_id)
                log :info, "Match account department_id: #{dept_id} at biz_id: #{b_id}"
                true
              end
            end
          end
        end

        def department_lists
          data = department_info.is_a?(Hash) ? department_info['data'] : nil
          lists = data.is_a?(Hash) ? data['business_lists'] : nil
          raise InvalidResponseError, "OneID account-detail response has no business_lists" unless lists.is_a?(Array)

          lists.select { |b| b.is_a?(Hash) }
        end

        def allowed_departments
          options.departments.each_with_object({}) do |(biz, depts), h|
            h[normalize_id(biz)] = normalize_ids(depts)
          end
        end

        # OneID ids are long digit strings: compare them as exact strings, never as numbers.
        def normalize_id(id)
          id.to_s.strip
        end

        def normalize_ids(ids)
          Array(ids).map { |id| normalize_id(id) }.reject(&:empty?).to_set
        end

        def gitlab_auto_block
          return unless options.auto_block[:enabled]

          if options.auto_block[:gitlab_token].to_s.empty?
            log :error, "Auto block is enabled but auto_block.gitlab_token is empty"
            return
          end

          user = gitlab_find_user
          unless user
            log :info, "Auto block: no GitLab user linked to OneID account #{uid}"
            return
          end
          # do nothing if user has blocked
          return if user['state'] == "blocked"

          user_id = Integer(user['id'])
          gitlab_api_block_user(user_id)
          log :info, "Auto block gitlab id: #{user_id}, account_id #{uid} for #{options.name} successful."
        rescue StandardError => e
          log :error, "Auto block account #{uid} for #{options.name} error #{e.class}: #{e.message}"
        end

        # Only a user whose identity matches this provider and uid exactly is returned,
        # so a filter that GitLab ignores can never block someone else.
        def gitlab_find_user
          users = execute_request(:get, "/api/v4/users", params: {provider: options.name, extern_uid: uid})
          return nil unless users.is_a?(Array)

          users.find do |u|
            u.is_a?(Hash) && Array(u['identities']).any? do |i|
              i.is_a?(Hash) && i['provider'].to_s == options.name.to_s && i['extern_uid'].to_s == uid
            end
          end
        end

        def gitlab_api_block_user(user_id)
          execute_request(:post, "/api/v4/users/#{Integer(user_id)}/block")
        end

        def gitlab_connection
          @gitlab_connection ||= begin
            base = options.auto_block[:gitlab_api].to_s
            uri = URI.parse(base)
            unless uri.scheme == "https" || (uri.scheme == "http" && LOOPBACK_HOSTS.include?(uri.hostname))
              raise ArgumentError, "auto_block.gitlab_api must use https (plain http is allowed only for localhost)"
            end

            Faraday.new(url: base, request: {
              open_timeout: options.auto_block[:open_timeout] || 5,
              timeout: options.auto_block[:timeout] || 10
            })
          end
        end

        def execute_request(verb, path, params: nil)
          headers = {'PRIVATE-TOKEN' => options.auto_block[:gitlab_token].to_s}
          response = begin
            gitlab_connection.run_request(verb, path, nil, headers) do |req|
              req.params.update(params) if params
            end
          rescue Faraday::TimeoutError => e
            raise TimeoutError, e
          rescue Faraday::ConnectionFailed => e
            raise ConnectionError, e
          end

          # The response body is not logged: it may echo user data.
          raise ConnectionError, "Gitlab api return error #{response.status}" if response.status >= 300

          body = response.body.to_s
          body.empty? ? nil : JSON.parse(body)
        end
    end
  end
end

OmniAuth.config.add_camelization "oauth2_oneid", "OAuth2OneID"
