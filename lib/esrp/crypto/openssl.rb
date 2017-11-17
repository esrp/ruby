# frozen_string_literal: true
require 'openssl'

module ESRP
  class Crypto
    ##
    # Class: OpenSSL crypto engine
    #
    # Provides:
    # - hash: SHA1, SHA256, SHA384, SHA512
    # - kdf: pbkdf2 with selected hash, legacy implementation H(salt | password)
    # - mac: hmac with selected hash, legacy H(message | key)
    #
    # Defaults to SHA256_PBKDF2_HMAC
    #
    class OpenSSL < self
      DEFAULT_OPTIONS = {
        hash: 'SHA256',
        kdf:  'pbkdf2',
        mac:  'HMAC',
        hex:   false,
        kdf_iter: 20_000
      }.freeze
      def self.default_options; DEFAULT_OPTIONS; end

      ##
      # Constant: list of available hashes
      #
      HASH_CLASSES = {
        sha:    ::OpenSSL::Digest::SHA,
        sha1:   ::OpenSSL::Digest::SHA1,
        sha256: ::OpenSSL::Digest::SHA256,
        sha384: ::OpenSSL::Digest::SHA384,
        sha512: ::OpenSSL::Digest::SHA512
      }.freeze

      ALLOWED_HASH = Set[*HASH_CLASSES.keys].freeze
      ALLOWED_KDF  = Set['pbkdf2', 'legacy'].freeze
      ALLOWED_MAC  = Set['hmac', 'legacy'].freeze

      NotApplicableError = Class.new(ArgumentError)

      ##
      # Public: SRP's one-way hash function
      #
      # Params:
      # - values {Array(ESRP::Value)} values to be hashed
      #
      # Returns: {ESRP::Value} one-way hash function result
      #
      def H(*values)
        hasher = @hasher.new

        values.compact.each do |val|
          hasher.update(@hex ? val.hex : val.bin)
        end

        Value.new(hasher.digest)
      end

      ##
      # Public: password-based key derivation function
      #
      # Params:
      # - salt     {ESRP::Value} random generated salt (s)
      # - password {String}      plain-text password in UTF8 string or concatenated UTF8 string
      #
      # Returns: {ESRP::Value}
      #
      def password_hash(salt, password)
        result = if @legacy_kdf
          hasher = @hasher.new
          hasher.update(salt.hex)
          hasher.update(password)
          hasher.digest
        else
          hasher = @hasher.new
          ::OpenSSL::PKCS5.pbkdf2_hmac(password, salt.bin, @kdf_iter, hasher.digest_length, hasher)
        end

        Value.new(result)
      end

      ##
      # Abstract Public: keyed hash transform function, like HMAC
      #
      # Params:
      # - key {String|ESRP::Value}
      # - msg {String|ESRP::Value}
      #
      # Returns: {ESRP::Value}
      #
      def keyed_hash(key, msg)
        result = if @legacy_mac
          hasher = @hasher.new
          hasher.update(@hex ? msg.hex : msg.bin)
          hasher.update(@hex ? key.hex : key.bin)
          hasher.digest
        else
          ::OpenSSL::HMAC.digest(@hasher.new, key.bin, msg.bin)
        end

        Value.new(result)
      end

      ##
      # Abstract Public: random string generator
      #
      # Params:
      # - bytes_length {Integer} length of desired generated bytes
      #
      # Returns: {ESRP::Value}
      #
      def random(bytes_length)
        Value.new(::OpenSSL::Random.random_bytes(bytes_length))
      end

      ##
      # Abstract Public: constant-time string comparison
      #
      # Compare two strings avoiding timing attacks
      #
      # Params:
      # - a {String|ESRP::Value}
      # - b {String|ESRP::Value}
      #
      # Returns: {Boolean} true if strings are equal
      #
      def secure_compare(a, b)
        a = a.hex
        b = b.hex
        return false unless a.bytesize == b.bytesize

        l = a.unpack('C*')

        r = 0
        i = -1
        b.each_byte { |v| r |= v ^ l[i+=1] }
        r == 0
      end

    private

      ##
      # Private: process crypto options
      #
      def process_options(options)
        @hex = options[:hex]
        @kdf_iter = options[:kdf_iter]

        set_hash(options[:hash])
        set_kdf(options[:kdf])
        set_mac(options[:mac])
      end

      ##
      # Private: set hash name
      #
      def set_hash(name)
        hash_name = name.to_s.downcase.tr('-', '').to_sym

        fail NotApplicableError unless ALLOWED_HASH.include?(hash_name)

        @hasher = HASH_CLASSES[hash_name]
      end

      ##
      # Private: set key derivation function
      #
      def set_kdf(name)
        kdf = name.to_s.downcase

        fail NotApplicableError unless ALLOWED_KDF.include?(kdf)

        @legacy_kdf = kdf == 'legacy'
      end

      ##
      # Private: set message auth algorithm
      #
      def set_mac(name)
        mac = name.to_s.downcase

        fail NotApplicableError unless ALLOWED_MAC.include?(mac)

        @legacy_mac = mac == 'legacy'
      end
    end
  end
end
