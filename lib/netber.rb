# $Id$
#
# NET::BER
# Mixes ASN.1/BER convenience methods into several standard classes.
# Also provides BER parsing functionality.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006 by Francis Cianfrocca. All Rights Reserved.
#
# Gmail: garbagecat20
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
#---------------------------------------------------------------------------
#
#




module Net

  module BER

  class BerError < Exception; end

  TagClasses = [:universal, :application, :context_specific, :private]

  # This module is for mixing into IO and IO-like objects.
  module BERParser

    BuiltinSyntax = {
      :universal => {
        1 => :boolean,
        2 => :integer,
        4 => :string,
        10 => :integer,
        16 => :array,
        17 => :array,
      }
    }

    #
    # read_ber
    #
    def read_ber syntax=nil
      eof? and return nil

      id = getc  # don't trash this value, we'll use it later
      tag = id & 31
      tag < 31 or raise BerError.new( "unsupported tag encoding: #{id}" )
      tagclass = TagClasses[ id >> 6 ]
      constructed = (id & 0x20 != 0)

      n = getc
      lengthlength,contentlength = if n <= 127
        [1,n]
      else
        j = (0...(n & 127)).inject(0) {|mem,x| mem = (mem << 8) + getc}
        [1 + (n & 127), j]
      end

      newobj = read contentlength

      objtype = (ot = BuiltinSyntax[tagclass]) && ot[tag]
      objtype = objtype || (syntax && (ot = syntax[tagclass]) && ot[tag])
      obj = case objtype
      when :boolean
        raise BerError.new( "boolean unimplemented- fix this now, dummy" )
      when :string
        newobj.dup
      when :integer
        j = 0
        newobj.each_byte {|b| j = (j << 8) + b}
        j
      when :array
        seq = []
        sio = StringIO.new newobj
        while e = sio.read_ber(syntax); seq << e; end
        seq
      else
        raise BerError.new( "unsupported object type: class=#{tagclass}, tag=#{tag}" )
      end

      # Add the identifier bits into the object if it's a String or an Array.
      # We can't add extra stuff to Fixnums and booleans, not that it makes much sense anyway.
      obj and ([String,Array].include? obj.class) and obj.instance_eval "def ber_identifier; #{id}; end"
      obj

    end

  end # module BERParser
  end # module BER

end # module Net


class IO
  include Net::BER::BERParser
end

require "stringio"
class StringIO
  include Net::BER::BERParser
end


class String
  def read_ber syntax=nil
    StringIO.new(self).read_ber
  end
end



#----------------------------------------------


class FalseClass
  #
  # to_ber
  #
  def to_ber
    "\001\001\000"
  end
end


class TrueClass
  #
  # to_ber
  #
  def to_ber
    "\001\001\001"
  end
end



class Fixnum
  #
  # to_ber
  #
  def to_ber
    i = [self].pack('w')
    [2, i.length].pack("CC") + i
  end

  #
  # to_ber_enumerated
  #
  def to_ber_enumerated
    i = [self].pack('w')
    [10, i.length].pack("CC") + i
  end

  #
  # to_ber_length_encoding
  #
  def to_ber_length_encoding
    if self <= 127
      [self].pack('C')
    else
      i = [self].pack('N').sub(/^[\0]+/,"")
      [0x80 + i.length].pack('C') + i
    end
  end

end # class Fixnum


class Bignum

  def to_ber
    i = [self].pack('w')
    i.length > 126 and raise Net::BER::BerError.new( "range error in bignum" )
    [2, i.length].pack("CC") + i
  end

end



class String
  #
  # to_ber
  # A universal octet-string is tag number 4,
  # but others are possible depending on the context, so we
  # let the caller give us one.
  #
  def to_ber code = 4
    [code].pack('C') + length.to_ber_length_encoding + self
  end

  #
  # to_ber_application_string
  # TODO. WARNING, IS THIS WRONG? Shouldn't app-specific string
  # have a prefix of 0x40?
  #
  def to_ber_application_string code
    to_ber( 0x80 + code )
  end

  #
  # to_ber_contextspecific
  #
  def to_ber_contextspecific code
    to_ber( 0x80 + code )
  end

end # class String



class Array
  #
  # to_ber_appsequence
  # An application-specific sequence usually gets assigned
  # a tag that is meaningful to the particular protocol being used.
  # This is different from the universal sequence, which usually
  # gets a tag value of 16.
  # Now here's an interesting thing: We're adding the X.690
  # "application constructed" code at the top of the tag byte (0x60),
  # but some clients, notably ldapsearch, send "context-specific
  # constructed" (0xA0). The latter would appear to violate RFC-1777,
  # but what do I know? We may need to change this.
  #

  def to_ber                 id = 0; to_ber_seq_internal( 0x30 + id ); end
  def to_ber_set             id = 0; to_ber_seq_internal( 0x31 + id ); end
  def to_ber_sequence        id = 0; to_ber_seq_internal( 0x30 + id ); end
  def to_ber_appsequence     id = 0; to_ber_seq_internal( 0x60 + id ); end
  def to_ber_contextspecific id = 0; to_ber_seq_internal( 0xA0 + id ); end

  private
  def to_ber_seq_internal code
    s = self.to_s
    [code].pack('C') + s.length.to_ber_length_encoding + s
  end

end # class Array



#----------------------------------------------

if __FILE__ == $0
  puts "No default action"
end



