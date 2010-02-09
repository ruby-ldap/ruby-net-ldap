module Net
  module BER
    module BERParser
      # The order of these follows the class-codes in BER.
      # Maybe this should have been a hash.
      TagClasses = [:universal, :application, :context_specific, :private]

      BuiltinSyntax = Net::BER.compile_syntax( {
    	  :universal => {
     	    :primitive => {
         	  1 => :boolean,
           	2 => :integer,
         		4 => :string,
         		5 => :null,
         		6 => :oid,
         		10 => :integer,
         		13 => :string # (relative OID)
     	    },
     	    :constructed => {
     		    16 => :array,
     		    17 => :array
     	    }
     	  },
     	  :context_specific => {
     	    :primitive => {
     		    10 => :integer
     	    }
     	  }
      })

      #
      # read_ber
      # TODO: clean this up so it works properly with partial
      # packets coming from streams that don't block when
      # we ask for more data (like StringIOs). At it is,
      # this can throw TypeErrors and other nasties.
      #--
      # BEWARE, this violates DRY and is largely equal in functionality to
      # read_ber_from_string. Eventually that method may subsume the functionality
      # of this one.
      #
      def read_ber syntax=nil
       # don't bother with this line, since IO#getc by definition returns nil on eof.
       #return nil if eof?

       # here we'll create two different procs, one for 1.8 and one for 1.9
       # the reason being getc doesn't return a byte value in 1.9, so we need to 
       # get the byte code out of the 1.9 encoded string

       if RUBY_VERSION =~ /^1\.9/
         fetch_byte = Proc.new { getc.bytes.first }
        elsif RUBY_VERSION =~ /^1\.8/
      		fetch_byte = Proc.new { getc }
      	end

         id = fetch_byte.call or return nil  # don't trash this value, we'll use it later
         #tag = id & 31
         #tag < 31 or raise BerError.new( "unsupported tag encoding: #{id}" )
         #tagclass = TagClasses[ id >> 6 ]
         #encoding = (id & 0x20 != 0) ? :constructed : :primitive

         n = fetch_byte.call
         lengthlength,contentlength = if n <= 127
           [1,n]
         else
           # Replaced the inject because it profiles hot.
           #j = (0...(n & 127)).inject(0) {|mem,x| mem = (mem << 8) + getc}
           j = 0
           read( n & 127 ).each_byte {|n1| j = (j << 8) + n1}
           [1 + (n & 127), j]
         end

         newobj = read contentlength

         # This exceptionally clever and clear bit of code is verrrry slow.
         objtype = (syntax && syntax[id]) || BuiltinSyntax[id]


         # == is expensive so sort this if/else so the common cases are at the top.
         obj = if objtype == :string
           #(newobj || "").dup
           s = BerIdentifiedString.new( newobj || "" )
           s.ber_identifier = id
           s
         elsif objtype == :integer
           j = 0
           newobj.each_byte {|b| j = (j << 8) + b}
           j
         elsif objtype == :oid
        # cf X.690 pgh 8.19 for an explanation of this algorithm.
        # Potentially not good enough. We may need a BerIdentifiedOid
        # as a subclass of BerIdentifiedArray, to get the ber identifier
        # and also a to_s method that produces the familiar dotted notation.
        oid = newobj.unpack("w*")
        f = oid.shift
        g = if f < 40
            [0, f]
        elsif f < 80
            [1, f-40]
        else
            [2, f-80] # f-80 can easily be > 80. What a weird optimization.
        end
        oid.unshift g.last
        oid.unshift g.first
        oid
         elsif objtype == :array
           #seq = []
           seq = BerIdentifiedArray.new
           seq.ber_identifier = id
           sio = StringIO.new( newobj || "" )
           # Interpret the subobject, but note how the loop
           # is built: nil ends the loop, but false (a valid
           # BER value) does not!
           while (e = sio.read_ber(syntax)) != nil
             seq << e
           end
           seq
         elsif objtype == :boolean
           newobj != "\000"
         elsif objtype == :null
        n = BerIdentifiedNull.new
        n.ber_identifier = id
        n
         else
           #raise BerError.new( "unsupported object type: class=#{tagclass}, encoding=#{encoding}, tag=#{tag}" )
           raise BerError.new( "unsupported object type: id=#{id}" )
         end

         # Add the identifier bits into the object if it's a String or an Array.
         # We can't add extra stuff to Fixnums and booleans, not that it makes much sense anyway.
         # Replaced this mechanism with subclasses because the instance_eval profiled too hot.
         #obj and ([String,Array].include? obj.class) and obj.instance_eval "def ber_identifier; #{id}; end"
         #obj.ber_identifier = id if obj.respond_to?(:ber_identifier)
         obj

       end

          #--
          # Violates DRY! This replicates the functionality of #read_ber.
          # Eventually this method may replace that one.
          # This version of #read_ber behaves properly in the face of incomplete
          # data packets. If a full BER object is detected, we return an array containing
          # the detected object and the number of bytes consumed from the string.
          # If we don't detect a complete packet, return nil.
          #
          # Observe that weirdly we recursively call the original #read_ber in here.
          # That needs to be fixed if we ever obsolete the original method in favor of this one.
          def read_ber_from_string str, syntax=nil
      	id = str[0] or return nil
      	n = str[1] or return nil
      	n_consumed = 2
      	lengthlength,contentlength = if n <= 127
      	    [1,n]
      	else
      	    n1 = n & 127
      	    return nil unless str.length >= (n_consumed + n1)
      	    j = 0
      	    n1.times {
      		j = (j << 8) + str[n_consumed]
      		n_consumed += 1
      	    }
      	    [1 + (n1), j]
      	end

      	return nil unless str.length >= (n_consumed + contentlength)
      	newobj = str[n_consumed...(n_consumed + contentlength)]
      	n_consumed += contentlength

      	objtype = (syntax && syntax[id]) || BuiltinSyntax[id]

      	# == is expensive so sort this if/else so the common cases are at the top.
      	obj = if objtype == :array
      	    seq = BerIdentifiedArray.new
      	    seq.ber_identifier = id
      	    sio = StringIO.new( newobj || "" )
      	    # Interpret the subobject, but note how the loop
      	    # is built: nil ends the loop, but false (a valid
      	    # BER value) does not!
      	    # Also, we can use the standard read_ber method because
      	    # we know for sure we have enough data. (Although this
      	    # might be faster than the standard method.)
      	    while (e = sio.read_ber(syntax)) != nil
      		seq << e
      	    end
      	    seq
      	elsif objtype == :string
      	    s = BerIdentifiedString.new( newobj || "" )
      	    s.ber_identifier = id
      	    s
      	elsif objtype == :integer
      	    j = 0
      	    newobj.each_byte {|b| j = (j << 8) + b}
      	    j
      	elsif objtype == :oid
      	    # cf X.690 pgh 8.19 for an explanation of this algorithm.
      	    # Potentially not good enough. We may need a BerIdentifiedOid
      	    # as a subclass of BerIdentifiedArray, to get the ber identifier
      	    # and also a to_s method that produces the familiar dotted notation.
      	    oid = newobj.unpack("w*")
      	    f = oid.shift
      	    g = if f < 40
      		[0,f]
      	    elsif f < 80
      		[1, f-40]
      	    else
      		[2, f-80] # f-80 can easily be > 80. What a weird optimization.
      	    end
      	    oid.unshift g.last
      	    oid.unshift g.first
      	    oid
      	elsif objtype == :boolean
      	    newobj != "\000"
      	elsif objtype == :null
      	    n = BerIdentifiedNull.new
      	    n.ber_identifier = id
      	    n
      	else
      	    raise BerError.new( "unsupported object type: id=#{id}" )
      	end

      	[obj, n_consumed]
      end	    
    end
  end
end