# $Id$
#
# LDAP Entry (search-result) support classes
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




module Net
class LDAP


  class Entry

    def initialize dn = nil
      @myhash = Hash.new {|k,v| k[v] = [] }
      self[:dn] = [dn]
    end


    def []= name, value
      sym = name.to_s.downcase.intern
      @myhash[sym] = value
    end

    def [] name
      unless name.is_a?(Symbol)
        name = name.to_s.downcase.intern
      end
      @myhash[name]
    end

    def dn
      self[:dn].shift
    end

    def attribute_names
      @myhash.keys
    end


  end # class Entry


end # class LDAP
end # module Net


