# frozen_string_literal: true

module ESRP
  ##
  # Class: value object
  #
  # Allows representation-independent operations on SRP values.
  #
  # While most of the crypto works with binary representation,
  # all the transfers between client and server usually utilize
  # hex strings and math operations uses integers.
  #
  class Value
    ##
    # Constructor:
    #
    # Params:
    # - value {String|Integer} byte string, hexadecimal string or integer
    #
    def initialize(value)
      if value.is_a?(Integer)
        @int = value
      elsif value.encoding == Encoding::BINARY
        @bin = value
      else
        @hex = value
      end
    end

    ##
    # Represent value as binary string
    #
    # Returns: {String} in binary encoding
    #
    def bin
      @bin ||= [hex].pack('H*')
    end

    ##
    # Represent value as hexadecimal string
    #
    # Note that the hex representation of bytes here done with padding,
    # so, for example '4d2' becomes '04d2'.
    #
    # Returns: {String} hexadecimal in UTF8
    #
    def hex
      @hex ||= if @bin
        @bin.unpack('H*').first
      else
        hex_str = @int.to_s(16)
        (hex_str.length.odd? ? '0' + hex_str : hex_str).downcase
      end
    end

    ##
    # Represent value as integer
    #
    # Returns: {Integer}
    #
    def int
      @int ||= hex.to_i(16)
    end
  end
end
