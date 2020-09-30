# frozen_string_literal: true

require_relative 'jwk/key_abstract'
require_relative 'jwk/rsa'
require_relative 'jwk/ec'
require_relative 'jwk/hmac'
require_relative 'jwk/key_finder'

module JWT
  module JWK
    MAPPINGS = {
      'RSA' => ::JWT::JWK::RSA,
      OpenSSL::PKey::RSA => ::JWT::JWK::RSA,
      'oct' => ::JWT::JWK::HMAC,
      String => ::JWT::JWK::HMAC,
      'EC' => ::JWT::JWK::EC,
      OpenSSL::PKey::EC => ::JWT::JWK::EC
    }.freeze

    class << self
      def import(jwk_data)
        jwk_kty = jwk_data[:kty] || jwk_data['kty']
        raise JWT::JWKError, 'Key type (kty) not provided' unless jwk_kty

        MAPPINGS.fetch(jwk_kty.to_s) do |kty|
          raise JWT::JWKError, "Key type #{kty} not supported"
        end.import(jwk_data)
      end

      def create_from(keypair)
        MAPPINGS.fetch(keypair.class) do |klass|
          raise JWT::JWKError, "Cannot create JWK from a #{klass.name}"
        end.new(keypair)
      end

      alias new create_from
    end
  end
end
