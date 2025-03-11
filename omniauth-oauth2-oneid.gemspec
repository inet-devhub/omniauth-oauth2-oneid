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
  spec.add_dependency 'rake', '~> 13.2'
  spec.add_dependency 'faraday', '~> 2.12', '>= 2.12.2'
end
