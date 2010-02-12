# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{net-ldap}
  s.version = "0.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = [["Kaspar Schiess", "kaspar.schiess@absurd.li"]]
  s.date = %q{2010-02-12}
  s.description = %q{Pure Ruby LDAP library}
  s.files = ["COPYING", "History.txt", "LICENSE", "Manifest.txt", "pre-setup.rb", "Rakefile", "README.txt", "Release-Announcement", "setup.rb", "test", "lib/net", "lib/net/ber", "lib/net/ber/ber_parser.rb", "lib/net/ber.rb", "lib/net/ldap", "lib/net/ldap/core_ext", "lib/net/ldap/core_ext/all.rb", "lib/net/ldap/core_ext/array.rb", "lib/net/ldap/core_ext/bignum.rb", "lib/net/ldap/core_ext/false_class.rb", "lib/net/ldap/core_ext/fixnum.rb", "lib/net/ldap/core_ext/string.rb", "lib/net/ldap/core_ext/true_class.rb", "lib/net/ldap/dataset.rb", "lib/net/ldap/entry.rb", "lib/net/ldap/filter.rb", "lib/net/ldap/pdu.rb", "lib/net/ldap/psw.rb", "lib/net/ldap.rb", "lib/net/ldif.rb", "lib/net/snmp.rb", "lib/net.rb"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{What this thing does}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
