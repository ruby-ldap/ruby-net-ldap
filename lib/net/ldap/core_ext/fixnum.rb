module Net
  class LDAP
    module Extensions
      module Fixnum
        def to_ber
          "\002" + to_ber_internal
        end

        def to_ber_enumerated
          "\012" + to_ber_internal
        end

        def to_ber_length_encoding
          if self <= 127
            [self].pack('C')
          else
            i = [self].pack('N').sub(/^[\0]+/,"")
            [0x80 + i.length].pack('C') + i
          end
        end

        # Generate a BER-encoding for an application-defined INTEGER.
        # Example: SNMP's Counter, Gauge, and TimeTick types.
        #
        def to_ber_application tag
            [0x40 + tag].pack("C") + to_ber_internal
        end

        #--
        # Called internally to BER-encode the length and content bytes of a Fixnum.
        # The caller will prepend the tag byte.
        def to_ber_internal
          # PLEASE optimize this code path. It's awfully ugly and probably slow.
          # It also doesn't understand negative numbers yet.
          raise Net::BER::BerError.new( "range error in fixnum" ) unless self >= 0
          z = [self].pack("N")
          zlen = if self < 0x80
      	1
          elsif self < 0x8000
      	2
          elsif self < 0x800000
      	3
          else
      	4
          end
          [zlen].pack("C") + z[0-zlen,zlen]
        end
        private :to_ber_internal
      end
    end
  end
end