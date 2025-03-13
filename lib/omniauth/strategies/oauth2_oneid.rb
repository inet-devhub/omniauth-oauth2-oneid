# frozen_string_literal: true

require 'omniauth-oauth2'
require 'faraday'
require 'json'

module OmniAuth
  module Strategies
    ConnectionError = Class.new(Faraday::ConnectionFailed)
    TimeoutError = Class.new(Faraday::TimeoutError)
  
    class OAuth2OneID < OmniAuth::Strategies::OAuth2
      option :name, "oauth2_oneid"
      option :provider_ignores_state, true
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
      option :businesses, []
      option :departments, {}
      option :auto_block,
      {
        enabled: false,
        gitlab_api: "http://localhost",
        gitlab_token: ""
      }

      # Get uid
      uid do
        user_path['id'].to_s
      end

      # Get account info
      info do
        hash = {
          name: "#{user_path['account_title_th']}#{user_path['first_name_th']} #{user_path['last_name_th']}",
          email: user_path['thai_email'],
          email_verified: user_path['thai_email'],
          urls: {
            oneid: "https://one.th/portal_index"
          }
        }
        if user_path['account_category '] != "Residential"
          hash['name'] = "#{user_path['account_title_eng']} #{user_path['first_name_eng']} #{user_path['last_name_eng']}"
        end

        if !check_business
          gitlab_auto_block
          raise "Forbidden. Unauthorized access restricted."
        end

        hash
      end

      extra do
        hash = {}
        hash[:id_info] = user_path
        hash[:business_info] = business_info
        hash[:deepartment_info] = deepartment_info
        if business_info['data'].empty?
          gitlab_auto_block
          raise "Forbidden. Unauthorized access restricted."
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

      def deepartment_info
        @department_info || access_token.get(options.client_options[:department_url]).parsed
      end
  
      def authorize_params
        params = super
        puts params.inspect
        params.transform_values { |v| v.respond_to?(:call) ? v.call(request) : v }
      end

      def callback_url
        options.client_options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      protected
        def build_access_token
          verifier = request.params["code"]
          client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
        end

        def user_path
          raw_info['data']
        end

        def check_business
          # Check department 1st if configured
          if !options.departments.empty?
            return check_department
          end

          # Check business 2nd
          return true unless !options.businesses.empty?
          b_set = options.businesses.to_set
          business_info['data'].each do |b|
            id = b[:id]
            if b_set.include?(id)
              return true
            end
          end
          false
        end

        def check_department
          deepartment_info['data']['business_lists'].each do |b|
            b_id = b[:id]
            if options.departments.include?(b_id)
              # Option
              dept_set = options.departments[b_id].to_set
              b[:account_roles].each do |a|
                if dept_set.include?(a[:dept_id])
                  log :info, "Match account department_id: #{a[:dept_id]} at biz_id: #{b_id}"
                  return true
                end
              end
            end
          end
          false
        end

        def gitlab_auto_block
          if !options.auto_block[:enabled]
            return
          end

          users = gitlab_api_get_user
          if users.any?
            # do nothing if user has blocked
            if users.first['state'] == "blocked"
              return
            end
            user_id = users.first['id']
            gitlab_api_block_user(user_id)
            log :info, "Auto block gitlab id: #{user_id}, account_id #{uid} for #{options.name} successful."
          end
        rescue => e
          log :error, "Auto block account #{uid} for #{options.name} error #{e}"
        end

        def gitlab_api_get_user
          execute_request(:get, "/api/v4/users", {params: {provider: options.name, extern_uid: uid}, headers: {'PRIVATE-TOKEN': options.auto_block[:gitlab_token]}})
        end

        def gitlab_api_block_user(user_id)
          execute_request(:post, "/api/v4/users/#{user_id}/block", {headers: {'PRIVATE-TOKEN': options.auto_block[:gitlab_token]}})
        end

        def execute_request(verb, url, opts = {})
          @connection ||= Faraday.new(options.auto_block[:gitlab_api], {})

          url = @connection.build_url(url).to_s
          begin
            response = @connection.run_request(verb, url, opts[:body], opts[:headers]) do |req|
              req.params.update(opts[:params]) if opts[:params]
              yield(req) if block_given?
            end
          rescue Faraday::ConnectionFailed => e
            raise ConnectionError, e
          rescue Faraday::TimeoutError => e
            raise TimeoutError, e
          end

          if response.status >= 300
            raise ConnectionError, "Gitlab api return error #{response.status} #{response.body}"
          end
          JSON.parse(response.body)
        end
    end
  end
end

OmniAuth.config.add_camelization "oauth2_oneid", "OAuth2OneID"
