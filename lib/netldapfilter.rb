# $Id$
#
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006 by Francis Cianfrocca. All Rights Reserved.
#
# Gmail: garbagecat10
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
class LDAP

class Filter

  def initialize op, a, b
    @op = op
    @left = a
    @right = b
  end

  def Filter::eq a, b; Filter.new :eq, a, b; end
  def Filter::ne a, b; Filter.new :ne, a, b; end
  def Filter::gt a, b; Filter.new :gt, a, b; end
  def Filter::lt a, b; Filter.new :lt, a, b; end
  def Filter::ge a, b; Filter.new :ge, a, b; end
  def Filter::le a, b; Filter.new :le, a, b; end

  def & a; Filter.new :and, self, a; end
  def | a; Filter.new :or, self, a; end

  # This operator can't be !, evidently. Try it.
  def ~@; Filter.new :not, self, nil; end

  def to_s
    case @op
    when :ne
      "(!(#{@left}=#{@right}))"
    when :eq
      "(#{@left}=#{@right})"
    when :gt
      "#{@left}>#{@right}"
    when :lt
      "#{@left}<#{@right}"
    when :ge
      "#{@left}>=#{@right}"
    when :le
      "#{@left}<=#{@right}"
    when :and
      "(&(#{@left})(#{@right}))"
    when :or
      "(|(#{@left})(#{@right}))"
    when :not
      "(!(#{@left}))"
    else
      raise "invalid or unsupported operator in LDAP Filter"
    end
  end


  #
  # to_ber
  # Filter ::=
  #     CHOICE {
  #         and            [0] SET OF Filter,
  #         or             [1] SET OF Filter,
  #         not            [2] Filter,
  #         equalityMatch  [3] AttributeValueAssertion,
  #         substrings     [4] SubstringFilter,
  #         greaterOrEqual [5] AttributeValueAssertion,
  #         lessOrEqual    [6] AttributeValueAssertion,
  #         present        [7] AttributeType,
  #         approxMatch    [8] AttributeValueAssertion
  #     }
  #
  # SubstringFilter
  #     SEQUENCE {
  #         type               AttributeType,
  #         SEQUENCE OF CHOICE {
  #             initial        [0] LDAPString,
  #             any            [1] LDAPString,
  #             final          [2] LDAPString
  #         }
  #     }
  #
  # Parsing substrings is a little tricky.
  # We use the split method to break a string into substrings
  # delimited by the * (star) character. But we also need
  # to know whether there is a star at the head and tail
  # of the string. A Ruby particularity comes into play here:
  # if you split on * and the first character of the string is
  # a star, then split will return an array whose first element
  # is an _empty_ string. But if the _last_ character of the
  # string is star, then split will return an array that does
  # _not_ add an empty string at the end. So we have to deal
  # with all that specifically.
  #
  def to_ber
    case @op
    when :eq
      if @right == "*"          # present
        @left.to_ber_application_string 7
      elsif @right =~ /[\*]/    #substring
        ary = @right.split( /[\*]+/ )
        final_star = @right =~ /[\*]$/
        initial_star = ary.first == "" and ary.shift

        seq = []
        unless initial_star
          seq << ary.shift.to_ber_contextspecific(0)
        end
        n_any_strings = ary.length - (final_star ? 0 : 1)
        p n_any_strings
        n_any_strings.times {
          seq << ary.shift.to_ber_contextspecific(1)
        }
        unless final_star
          seq << ary.shift.to_ber_contextspecific(2)
        end
        [@left.to_ber, seq.to_ber].to_ber_contextspecific 4
      else                      #equality
        [@left.to_ber, @right.to_ber].to_ber_contextspecific 3
      end
    when :and
      ary = [@left.coalesce(:and), @right.coalesce(:and)].flatten
      ary.map {|a| a.to_ber}.to_ber_contextspecific( 0 )
    when :or
      ary = [@left.coalesce(:or), @right.coalesce(:or)].flatten
      ary.map {|a| a.to_ber}.to_ber_contextspecific( 1 )
    when :not
        [@left.to_ber].to_ber_contextspecific 2
    else
      # ERROR, we'll return objectclass=* to keep things from blowing up,
      # but that ain't a good answer and we need to kick out an error of some kind.
      raise "unimplemented search filter"
    end
  end

  #
  # coalesce
  # This is a private helper method for dealing with chains of ANDs and ORs
  # that are longer than two. If BOTH of our branches are of the specified
  # type of joining operator, then return both of them as an array (calling
  # coalesce recursively). If they're not, then return an array consisting
  # only of self.
  #
  def coalesce operator
    if @op == operator
      [@left.coalesce( operator ), @right.coalesce( operator )]
    else
      [self]
    end
  end


end # class Net::LDAP::Filter

end # class Net::LDAP
end # module Net


#-----------------------------------

if __FILE__ == $0
  puts "No default action"
end

