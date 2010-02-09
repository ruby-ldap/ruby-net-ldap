module Net
  class LDAP
    module Extensions
      module String
        #
        # to_ber
        # A universal octet-string is tag number 4,
        # but others are possible depending on the context, so we
        # let the caller give us one.
        # The preferred way to do this in user code is via to_ber_application_sring
        # and to_ber_contextspecific.
        #
        def to_ber code = 4
          [code].pack('C') + length.to_ber_length_encoding + self
        end

        #
        # to_ber_application_string
        #
        def to_ber_application_string code
          to_ber( 0x40 + code )
        end

        #
        # to_ber_contextspecific
        #
        def to_ber_contextspecific code
          to_ber( 0x80 + code )
        end
        
        def read_ber syntax=nil
      	  StringIO.new(self).read_ber(syntax)
        end
          
        def read_ber! syntax=nil
      	  obj,n_consumed = read_ber_from_string(self, syntax)
      	  if n_consumed
      	    self.slice!(0...n_consumed)
      	    obj
      	  else
      	    nil
      	  end
        end
        
      end
    end
  end
end