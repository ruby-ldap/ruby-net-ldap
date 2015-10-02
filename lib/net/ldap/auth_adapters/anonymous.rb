require 'net/ldap/auth_adapters/simple'

Net::LDAP::AuthAdapter.register(:anonymous, Net::LDAP::AuthAdapters::Simple)
