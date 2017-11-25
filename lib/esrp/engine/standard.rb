module ESRP
  class Engine
    ##
    # Class: Default engine
    #
    # This engine doesn't involve username, uses "K" as a master secret
    # and doesn't perform XOR computation in "M".
    # Also, it tries to conform RFC5054 as much as possible.
    #
    class Standard < self
      ##
      # Public: Calculate private key (x)
      #
      #   x = KDF(s, p)
      #
      # Params:
      # - password {String}      plain-text password in UTF8 string
      # - salt     {ESRP::Value} random generated salt (s)
      # - username {String}      plain-text username in UTF8 string (not used here)
      #
      # Returns: {ESRP::Value} private key (x)
      #
      def calc_x(password, salt, _username=nil)
        crypto.password_hash(salt, password)
      end

      ##
      # Public: Calculate validation message (M) (M1 in some specs)
      #
      #   M = HMAC(K, A | s | B)
      #
      # Params:
      # - kk {ESRP::Value} private session key (K)
      # - aa {ESRP::Value} client ephemeral value (A)
      # - bb {ESRP::Value} server ephemeral value (B)
      # - ss {ESPR::Value} premaster secret (S) (not used here)
      # - salt     {ESRP::Value} random generated salt (s)
      # - username {String} plain-text username in UTF8 string (not used here)
      #
      # Returns: {ESRP::Value} validation message (M)
      #
      def calc_M(kk, aa, bb, _ss, salt, _username)
        val = aa.bin + salt.bin + bb.bin

        crypto.keyed_hash(kk, Value.new(val))
      end

      ##
      # Public: Calculate optional response validation message (HAMK) (M2 in some specs)
      #
      #   M2 = HMAC(K, A | M)
      #
      # Params:
      # - kk {ESRP::Value} private session key (K)
      # - aa {ESRP::Value} client ephemeral value (A)
      # - mm {ESRP::Value} validation message (M)
      # - ss {ESPR::Value} premaster secret (S) (not used here)
      #
      # Returns: {ESRP::Value}
      #
      def calc_M2(kk, aa, mm, _ss)
        crypto.keyed_hash(kk, aa.bin + mm.bin)
      end
    end
  end
end
