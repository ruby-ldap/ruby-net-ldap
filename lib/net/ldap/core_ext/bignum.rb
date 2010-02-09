module Net
  class LDAP
    module Extensions
      module Bignum

        def to_ber
          #i = [self].pack('w')
          #i.length > 126 and raise Net::BER::BerError.new( "range error in bignum" )
          #[2, i.length].pack("CC") + i

          # Ruby represents Bignums as two's-complement numbers so we may actually be
          # good as far as representing negatives goes.
          # I'm sure this implementation can be improved performance-wise if necessary.
          # Ruby's Bignum#size returns the number of bytes in the internal representation
          # of the number, but it can and will include leading zero bytes on at least
          # some implementations. Evidently Ruby stores these as sets of quadbytes.
          # It's not illegal in BER to encode all of the leading zeroes but let's strip
          # them out anyway.
          #
          sz = self.size
          out = "\000" * sz
          (sz*8).times {|bit|
      	if self[bit] == 1
      	    out[bit/8] += (1 << (bit % 8))
      	end
          }

          while out.length > 1 and out[-1] == 0
      	out.slice!(-1,1)
          end

          [2, out.length].pack("CC") + out.reverse
        end

      end
    end
  end
end