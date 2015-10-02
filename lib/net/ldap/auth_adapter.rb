module Net
  class LDAP
    class AuthAdapter
      def self.register(names, adapter)
        names = Array(names)
        @adapters ||= {}
        names.each do |name|
          @adapters[name] = adapter
        end
      end

      def self.[](name)
        @adapters[name]
      end

      def initialize(conn)
        @connection = conn
      end

      def bind
        raise "bind method must be overwritten"
      end
    end
  end
end
