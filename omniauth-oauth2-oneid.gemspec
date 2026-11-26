# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require_relative "lib/omniauth/oneid/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-oauth2-oneid"
  spec.version = OmniAuth::OAuth2OneID::VERSION
  spec.authors = ["Patcharapong"]
  spec.email = ["patcharp@live.com"]

  spec.summary = "OAuth2 SSO One ID"
  spec.description = "Configurable Strategy for One ID OAuth2 provider"
  spec.homepage = "https://github.com/inet-devhub/omniauth-oauth2-oneid"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end

  spec.require_paths = ['lib']

  spec.add_dependency 'omniauth-oauth2', '~> 1.8'
  # Security floors for transitive dependencies:
  # omniauth >= 2.2.0: CVE-2026-63183 (Host header injection; callback_url uses full_host)
  spec.add_dependency 'omniauth', '>= 2.2.0', '< 3'
  # oauth2 >= 2.0.22: CVE-2026-54603 (bearer token leaked on protocol-relative redirect)
  spec.add_dependency 'oauth2', '>= 2.0.22', '< 3'
  # faraday >= 2.14.3: CVE-2026-25765, CVE-2026-33637, CVE-2026-54297
  spec.add_dependency 'faraday', '~> 2.14', '>= 2.14.3'

  spec.add_development_dependency 'rake', '~> 13.2'
  spec.add_development_dependency 'minitest', '>= 5.20', '< 7'
  spec.add_development_dependency 'rack-test', '~> 2.1'
  spec.add_development_dependency 'rack-session', '>= 2.0', '< 3'
  spec.add_development_dependency 'webmock', '~> 3.23'
  spec.add_development_dependency 'bundler-audit', '~> 0.9'
end
