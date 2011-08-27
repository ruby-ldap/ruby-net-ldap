# -*- ruby encoding: utf-8 -*-
require 'stringio'

##
# BER extensions to the String class.
module Net::BER::Extensions::String
  ##
  # Converts a string to a BER string. Universal octet-strings are tagged
  # with 0x04, but other values are possible depending on the context, so we
  # let the caller give us one.
  #
  # User code should call either #to_ber_application_string or
  # #to_ber_contextspecific.
  def to_ber(code = 0x04)
    raw_string = to_raw_string
    raw_length = raw_string.length
    [code].pack('C') + raw_length.to_ber_length_encoding + raw_string
  end

  # Make a raw byte string version of this string
  def to_raw_string
      if respond_to?(:force_encoding)
        self.dup.force_encoding("ASCII-8BIT")
      else
        self
      end
  end
  private :to_raw_string

  ##
  # Creates an application-specific BER string encoded value with the
  # provided syntax code value.
  def to_ber_application_string(code)
    to_ber(0x40 + code)
  end

  ##
  # Creates a context-specific BER string encoded value with the provided
  # syntax code value.
  def to_ber_contextspecific(code)
    to_ber(0x80 + code)
  end

  ##
  # Nondestructively reads a BER object from this string.
  def read_ber(syntax = nil)
    StringIO.new(self).read_ber(syntax)
  end

  ##
  # Destructively reads a BER object from the string.
  def read_ber!(syntax = nil)
    io = StringIO.new(self)

    result = io.read_ber(syntax)
    self.slice!(0...io.pos)

    return result
  end
end
