# frozen_string_literal: true
require 'esrp/group'
require 'openssl' # FIXME - this is because of the lack of proper BigNumber implementation in ruby

module ESRP
  ##
  # Abstract Class: SRP calculation engine
  #
  # This class defines the foundation for SRP values computations
  # Different implementations may be constructed, basing on this class
  # There are 4 vectors for customizing as seen on different implementations:
  #
  # 1. x and M computation (see #calc_x and #calc_M)
  # 2. Crypto primitives (see ERSP::Crypto)
  # 3. Type conversion (see ESRP::Crypto#H and ESRP::Value)
  # 4. Padding (see #pad)
  #
  # So, to provide compatibility, we can use different engines and customize
  # ESRP::Crypto.
  # For example:
  #   Subclass of ESRP::Engine defines
  #     #calc_x as password_hash(s, p) ignoring the 'I' argument
  #     #calc_M as keyed_hash(S, A | B) ignoring 'K', 'I' and 's' args
  #     #calc_M2 as H(A | M | K) ignoring 'S' argument
  #     #pad do nothing (returns value as is)
  #   Subclass of ESRP::Crypto provides
  #     #H as SHA1 with hex string concatenation
  #     #password_hash as SHA1(salt | password)
  #     #keyed_hash as SHA1(value | key)
  # In this way, we can build Server or Client compatible with almost every existing
  # implementation. But if it's not necessary, the default engines are recommended.
  #
  # One more thing to mention: design docs says "All arithmetic is done modulo N",
  # but it's not clear what does it mean. After reviewing actual implementations,
  # the most popular interpretation is:
  #
  # * "a^b" operation treats as "a^b mod N"
  # * "B" have an additional "mod N" in the end (see https://www.computest.nl/blog/exploiting-two-buggy-srp-implementations/)
  #
  # Other interpretations are not supported, but could be monkey-patched (mostly
  # additional "(u * x mod N)" in client S).
  #
  # Glossary (as seen on http://srp.stanford.edu/design.html):
  #   N    A large safe prime (N = 2q+1, where q is prime)
  #   g    A generator modulo N
  #   k    Multiplier parameter k = H(N, g)
  #   s    User's salt
  #   I    Username
  #   p    Cleartext Password
  #   H()  One-way hash function
  #   ^    (Modular) Exponentiation
  #   u    Random scrambling parameter
  #   a,b  Secret ephemeral values
  #   A,B  Public ephemeral values
  #   x    Private key (derived from p and s)
  #   v    Password verifier
  #
  class Engine
    ##
    # Current crypto engine
    #
    # Returns: {ESRP::Crypto}
    #
    attr_reader :crypto

    ##
    # Constructor:
    #
    # Params:
    # - crypto {ESRP::Crypto} crypto engine
    # - group  {ESRP::Group}  group params
    #
    def initialize(crypto, group=Group[2048])
      @crypto = crypto
      @N = group.N
      @g = group.g
    end

    ##
    # Abstract Public: Calculate private key (x)
    #
    # This function is a keystone of verifier's (v) strengthness
    #
    # The SRP-6a design docs describes 'x' as:
    #
    #   x = H(s | p)
    #
    # However, different implementations and standards defines their own,
    # more complicated calculations:
    #
    #   x = H(s | H(I) | H(p))
    #   x = H(s | H(I | ":" | p)) - RFC2945, RFC5054
    #
    # All this calculations uses the same one-way hash function (SHA in general),
    # as for other computations, which is designed to be fast and not computationally
    # intensive. This can be improved by using more computational heavy algorithms.
    # Various password-based key derivation functions (such as bcrypt, scrypt, argon2)
    # can be a pretty good option. So, it can look like:
    #
    #   x = KDF(s, p)
    #
    # Also, the username (I) is frequently seen in calculation of 'x'. From one side,
    # it mitigates inpersonation attacks. From the other side, majority of the modern
    # webapps allows users to change their login or use different emails for auth. So
    # the username argument left optional. Various engine implementations may use or
    # skip it. IMPORTANT: server SHOULD implement some mechanism to limit unsuccessful
    # authentication attempts. Especially when using implementation without involving
    # username (I) in 'x'
    #
    # Finally, the preparation of username (I) and password (p) using the stringprep (RFC3454)
    # may apply. RFC5054 requires SASLprep profile (RFC4013) for stringprep.
    #
    # Papers
    # * http://srp.stanford.edu/ndss.html#itspub
    # * https://web.archive.org/web/20150403175113/http://www.leviathansecurity.com/wp-content/uploads/SpiderOak-Crypton_pentest-Final_report_u.pdf - page 12
    #
    # Params:
    # - password {String}      plain-text password in UTF8 string
    # - salt     {ESRP::Value} random generated salt (s)
    # - username {String}      plain-text username in UTF8 string (optional)
    #
    # Returns: {ESRP::Value} private key (x)
    #
    def calc_x(password, salt, username=nil)
      fail NotImplementedError
    end

    ##
    # Abstract Public: Calculate validation message (M) (M1 in some specs)
    #
    # Validation message is a proof of validity of private session key (K)
    # The SRP-6a design docs and RFC2945 describes ("One possible way is") 'M' as:
    #
    #   M = H(H(N) xor H(g) | H(I) | s | A | B | K)
    #
    # As with 'x' there are some differences between implementations:
    #
    #   M = H(A | B | S)
    #   M = H(A | B | K)
    #
    # The main sense for 'M' is to transmit 'K' without it's compromentation.
    # In first case, H(N) XOR H(g) adds additional computational heaviness and
    # a grain of salt, but they doesn't do too much, so all variants is pretty
    # good and the choice of formula depends on use case and is up to implementor.
    #
    # Also, the RFC2945 recommends usage of keyed hash transforms (like HMAC)
    # with 'K' as a key. Hardened implementation may look like:
    #
    #   M = HMAC(K, H(N) xor H(g) | H(I) | s | A | B)
    #
    # or
    #
    #   M = HMAC(K, A | s | B)
    #
    # or similar.
    #
    # Params:
    # - kk {ESRP::Value} private session key (K)
    # - aa {ESRP::Value} client ephemeral value (A)
    # - bb {ESRP::Value} server ephemeral value (B)
    # - ss {ESPR::Value} premaster secret (S)
    # - salt     {ESRP::Value} random generated salt (s)
    # - username {String} plain-text username in UTF8 string (optional)
    #
    # Returns: {ESRP::Value} validation message (M)
    #
    def calc_M(kk, aa, bb, ss, salt, username)
      fail NotImplementedError
    end

    ##
    # Abstract Public: Calculate optional response validation message (HAMK) (M2 in some specs)
    #
    #   M2 = H(A | M | K)
    #
    # Also seen as
    #
    #   M2 = H(A | M | S)
    #
    # Proves that the server has a valid verifier (v)
    #
    # As for M1, HMAC with 'K' as key may be used:
    #
    #   M2 = HMAC(K, A | M)
    #
    # Params:
    # - kk {ESRP::Value} private session key (K)
    # - aa {ESRP::Value} client ephemeral value (A)
    # - mm {ESRP::Value} validation message (M)
    # - ss {ESPR::Value} premaster secret (S)
    #
    # Returns: {ESRP::Value}
    #
    def calc_M2(kk, aa, mm, ss)
      fail NotImplementedError
    end

    ##
    # Multiplier parameter (k)
    #
    #   k = H(N | g)
    #   k = H(N | PAD(g)) - RFC5054
    #
    # Returns: {ESRP::Value} multiplier parameter (k)
    #
    def k
      @k ||= crypto.H(@N, pad(@g))
    end

    ##
    # Calculate password verifier (v)
    #
    #   v = g^x
    #
    # Params:
    # - x {ESRP::Value} private key (x)
    #
    # Returns: {ESRP::Value} password verifier (v)
    #
    def calc_v(x)
      mod_exp(@g, x)
    end

    ##
    # Calculate public client ephemeral value (A)
    #
    #   A = g^a
    #
    # The host MUST abort the authentication if A mod N == 0
    #
    # Params:
    # - a {ESRP::Value} secret client ephemeral value (a)
    #
    # Returns: {ESRP::Value} public client ephemeral value (A)
    #
    def calc_A(a)
      mod_exp(@g, a)
    end

    ##
    # Calculate public server ephemeral value (B)
    #
    #   B = kv + g^b % N
    #
    # The client MUST abort authentication if B % N == 0
    #
    # Note the additional mod N in the end: https://www.computest.nl/blog/exploiting-two-buggy-srp-implementations/
    #
    # Params:
    # - b {ESRP::Value} secret server ephemeral value (b)
    #
    # Returns: {ESRP::Value} public server ephemeral value (B)
    #
    def calc_B(b, v)
      result = (k.int * v.int + mod_exp(@g, b).int) % @N.int

      Value.new(result)
    end

    ##
    # Calculate random scrambling parameter (u)
    #
    #   u = H(A | B)
    #   u = H(PAD(A) | PAD(B))
    #
    # Params:
    # - aa {ESRP::Value} client ephemeral value (A)
    # - bb {ESRP::Value} server ephemeral value (B)
    #
    # Returns: {ESRP::Value} random scrambling parameter (u)
    #
    def calc_u(aa, bb)
      crypto.H(pad(aa), pad(bb))
    end

    ##
    # Calculate client session key (S)
    #
    #   S = (B - (k * g^x)) ^ (a + (u * x))
    #
    # Params:
    # - bb {ESRP::Value} public server ephemeral value (B)
    # - a  {ESRP::Value} secret client ephemeral value (a)
    # - x  {ESRP::Value} private key (x)
    # - u  {ESRP::Value} random scrambling parameter (u)
    #
    # Returns: {ESRP::Value} client session key (S)
    #
    def calc_client_S(bb, a, x, u)
      left  = bb.int - k.int * mod_exp(@g, x).int
      right = a.int + u.int * x.int

      mod_exp(Value.new(left), Value.new(right))
    end

    ##
    # Calculate server session key (S)
    #
    #   S = (A * v^u) ^ b
    #
    # Params:
    # - aa {ESRP::Value} client ephemeral value (A)
    # - b  {ESRP::Value} secret server ephemeral value (b)
    # - v  {ESRP::Value} password verifier (v)
    # - u  {ESRP::Value} random scrambling parameter (u)
    #
    # Returns: {ESRP::Value} server session key (S)
    #
    def calc_server_S(aa, b, v, u)
      mod_exp(Value.new(aa.int * mod_exp(v, u).int), b)
    end

    ##
    # Calculate private session key (K)
    #
    #   K = H(S)
    #
    # This key calculates independently on both client and server and may be used
    # as private key on later symmetric cryptography exchange between client and
    # server.
    #
    # Params:
    # - ss {ESPR::Value} premaster secret (S)
    #
    # Returns: {ESRP::Value} private session key (K)
    #
    def calc_K(ss)
      crypto.H(ss)
    end

  private

    ##
    # Private: left-pad value with zeroes
    #
    # According to RFC5054:
    # "If a conversion is explicitly specified with the operator PAD(), the integer
    # will first be implicitly converted, then the resultant byte-string will be
    # left-padded with zeros (if necessary) until its length equals the
    # implicitly-converted length of N."
    #
    def pad(value)
      Value.new(value.bin.rjust(@N.bin.length, "\x00"))
    end

    ##
    # Private: modular exponentation
    #
    # As mentioned above, this method reflects '^' operator in SRP
    # which interprets as 'a^b%N' ('a EXP b MOD N')
    #
    # Params:
    # - a {ESRP::Value}
    # - b {ESRP::Value}
    #
    # Returns: {ESRP::Value}
    #
    def mod_exp(a, b)
      Value.new(a.int.to_bn.mod_exp(b.int, @N.int).to_i)
    end
  end
end
