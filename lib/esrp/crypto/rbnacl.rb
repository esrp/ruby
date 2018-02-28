# frozen_string_literal: true
require 'rbnacl/libsodium'

module ESRP
  class Crypto
    class RbNaCl < self
      DEFAULT_OPTIONS = {
        hash: 'SHA256',
        kdf:  'scrypt'
      }.freeze

      ##
      # Constant: List of available password hashes
      #
      KDF_CLASSES = {
        scrypt: ::RbNaCl::PasswordHash::SCrypt,
        argon2: ::RbNaCl::PasswordHash::Argon2
      }.freeze

      KDF_OPTIONS = {
        scrypt: { opslimit: 2**20, memlimit: 2**24, digest_size: 64 },
        argon2: { opslimit: 5, memlimit: 2**24, digest_size: 64 }
      }.freeze

      ##
      # Constans: list of hash sizes
      #
      HASH_SIZES = {
        blake2b: 64,
        sha256: 32,
        sha512: 64
      }.freeze

      ##
      # Constant: Allowed key derivation functions
      #
      ALLOWED_KDF  = Set[*KDF_CLASSES.keys].freeze

      def self.default_options; DEFAULT_OPTIONS; end

      ##
      # Public: SRP's one-way hash function
      #
      # Params:
      # - values {Array(ESRP::Value)} values to be hashed
      #
      # Returns: {ESRP::Value} one-way hash function result
      #
      def H(*values)
        str = values.compact.reduce('') { |memo, val| memo + val.bin }

        Value.new(@hasher.call(str))
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
        kdf = @kdf.new(@kdf_options[:opslimit], @kdf_options[:memlimit], @kdf_options[:digest_size])

        Value.new(kdf.digest(password, salt.bin))
      end

      ##
      # Public: keyed hash transform function, like HMAC
      #
      # Params:
      # - key {String|ESRP::Value}
      # - msg {String|ESRP::Value}
      #
      # Returns: {ESRP::Value}
      #
      def keyed_hash(key, msg)
        Value.new(@hmac.new(key.bin.rjust(@hmac::KEYBYTES, "\x00")).auth(msg.bin))
      end

      ##
      # Abstract Public: generate salt
      #
      # Returns: {ESRP::Value}
      #
      def salt
        random
      end

      ##
      # Public: random string generator
      #
      # Params:
      # - bytes_length {Integer} length of desired generated bytes
      #
      # Returns: {ESRP::Value}
      #
      def random(bytes_length=@hash_size)
        Value.new(::RbNaCl::Random.random_bytes(bytes_length))
      end

      ##
      # Public: constant-time string comparison
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
        ah = ::RbNaCl::Hash.sha256(a)
        bh = ::RbNaCl::Hash.sha256(b)

        ::RbNaCl::Util.verify32(ah, bh)
      end

    private

      ##
      # Private: process crypto options
      #
      def process_options(options)
        @hash_size = HASH_SIZES[options[:hash].to_sym]

        set_hash(options[:hash], options[:blake_digest_size])
        set_kdf(options[:kdf], options[:kdf_options] || {})
        set_mac
      end

      ##
      # Private: set hash name
      #
      def set_hash(name, blake_digest_size)
        case name.to_s.downcase.tr('-', '')
          when 'sha256'
            @digest_size = 32
            @hasher = ->(str) { ::RbNaCl::Hash.sha256(str)  }
          when 'sha512'
            @digest_size = 64
            @hasher = ->(str) { ::RbNaCl::Hash.sha512(str)  }
          when 'blake2b'
            @digest_size = (blake_digest_size || 32).to_i
            fail NotApplicableError.new("digest size must be 32 or 64, not #{@digest_size}") if @digest_size != 32 && @digest_size != 64
            @hasher = ->(str) { ::RbNaCl::Hash.blake2b(str, digest_size: @digest_size) }
          else fail NotApplicableError.new("hash: '#{name}' is not a valid option, available options: sha256, sha512, blake2b")
        end
      end

      ##
      # Private: set key derivation function
      #
      def set_kdf(name, options)
        kdf_name = name.to_s.downcase.to_sym

        unless ALLOWED_KDF.include?(kdf_name)
          fail NotApplicableError.new("kdf: '#{kdf_name}' is not a valid option, available options: #{ALLOWED_KDF.to_a.join(', ')}")
        end

        @kdf = KDF_CLASSES[kdf_name]
        @kdf_options = KDF_OPTIONS[kdf_name].merge(options)
      end

      ##
      # Private: set message auth algorithm
      #
      def set_mac
        @hmac = @digest_size == 64 ? ::RbNaCl::HMAC::SHA512 : ::RbNaCl::HMAC::SHA256
      end
    end
  end
end
