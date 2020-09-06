# frozen_string_literal: true

module JWT
  module JWK
    class EC
      attr_reader :keypair

      KTY    = 'EC'.freeze
      BINARY = 2

      def initialize(keypair)
        raise ArgumentError, 'keypair must be of type OpenSSL::PKey::EC' unless keypair.is_a?(OpenSSL::PKey::EC)

        @keypair = keypair
      end

      def private?
        keypair.private?
      end

      def public_key
        keypair.public_key
      end

      def export
        case keypair.group.curve_name
        when 'prime256v1'; 'P-256'
          crv = 'P-256'
          x, y = keypair.public_key.to_bn.to_s(BINARY).unpack('xa32a32')
        when 'secp384r1';
          crv = 'P-384'
          x, y = keypair.public_key.to_bn.to_s(BINARY).unpack('xa48a48')
        when 'secp521r1'; 'P-521'
          crv = 'P-521'
          x, y = keypair.public_key.to_bn.to_s(BINARY).unpack('xa66a66')
        else
          raise "error!"
        end
        sequence = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(x, BINARY)),
                                            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(y, BINARY))])
        kid = OpenSSL::Digest::SHA256.hexdigest(sequence.to_der)
        {
          kty: KTY,
          crv: crv,
          x: encode_octets(x),
          y: encode_octets(y),
          kid: kid,
          d: (encode_open_ssl_bn(keypair.private_key) if keypair.private_key?),
        }.compact
      end

      def encode_octets(octets)
        ::Base64.urlsafe_encode64(octets, padding: false)
      end

      def encode_open_ssl_bn(key_part)
        ::Base64.urlsafe_encode64(key_part.to_s(BINARY), padding: false)
      end

      def self.import(jwk_data)
        jwk_crv = jwk_data[:crv] || jwk_data['crv']
        jwk_x = jwk_data[:x] || jwk_data['x']
        jwk_y = jwk_data[:y] || jwk_data['y']
        jwk_d = jwk_data[:d] || jwk_data['d']

        self.new(ec_pkey(jwk_crv, jwk_x, jwk_y, jwk_d))
      end

      def self.ec_pkey(jwk_crv, jwk_x, jwk_y, jwk_d=nil)
        curve = to_openssl_curve(jwk_crv)

        x = decode_octets(jwk_x)
        y = decode_octets(jwk_y)

        key = OpenSSL::PKey::EC.new(curve)

        point = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(curve),
          OpenSSL::BN.new([0x04, x, y].pack('Ca*a*'), 2)
        )

        key.public_key = point
        key.private_key = decode_open_ssl_bn(jwk_d) if jwk_d

        key
      end

      def self.to_openssl_curve(crv)
        # See RFC 5480 section 2.1.1.1 for help in navigating the
        # different aliases for these curves.
        case crv
        when 'P-256'; 'prime256v1'
        when 'P-384'; 'secp384r1'
        when 'P-521'; 'secp521r1'
        else raise 'Invalid curve provided'
        end
      end

      def self.decode_octets(jwk_data)
        ::Base64.urlsafe_decode64(jwk_data)
      end

      def self.decode_open_ssl_bn(jwk_data)
        OpenSSL::BN.new(::Base64.urlsafe_decode64(jwk_data), BINARY)
      end
    end
  end
end
