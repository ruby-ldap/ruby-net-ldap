require 'net/ldap/auth_adapters/simple'

Net::LDAP::AuthAdapter.register(:anon, Net::LDAP::AuthAdapters::Simple)
