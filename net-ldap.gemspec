# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{net-ldap}
  s.version = "0.1.1.20110316141115"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Francis Cianfrocca", "Emiel van de Laar", "Rory O'Connell", "Kaspar Schiess", "Austin Ziegler"]
  s.date = %q{2011-03-16}
  s.description = %q{Pure Ruby LDAP library.}
  s.email = ["blackhedd@rubyforge.org", "gemiel@gmail.com", "rory.ocon@gmail.com", "kaspar.schiess@absurd.li", "austin@rubyforge.org"]
  s.extra_rdoc_files = ["History.txt", "Manifest.txt", "README.txt", "Hacking.rdoc"]
  s.files = ["COPYING", "Hacking.rdoc", "History.txt", "LICENSE", "Manifest.txt", "README.txt", "Rakefile", "lib/net-ldap.rb", "lib/net/ber.rb", "lib/net/ber/ber_parser.rb", "lib/net/ber/core_ext.rb", "lib/net/ber/core_ext/array.rb", "lib/net/ber/core_ext/bignum.rb", "lib/net/ber/core_ext/false_class.rb", "lib/net/ber/core_ext/fixnum.rb", "lib/net/ber/core_ext/string.rb", "lib/net/ber/core_ext/true_class.rb", "lib/net/ldap.rb", "lib/net/ldap/dataset.rb", "lib/net/ldap/entry.rb", "lib/net/ldap/filter.rb", "lib/net/ldap/pdu.rb", "lib/net/ldap/psw.rb", "lib/net/ldif.rb", "lib/net/snmp.rb", "spec/integration/ssl_ber_spec.rb", "spec/spec.opts", "spec/spec_helper.rb", "spec/unit/ber/ber_spec.rb", "spec/unit/ber/core_ext/string_spec.rb", "spec/unit/ldap/entry_spec.rb", "spec/unit/ldap/filter_spec.rb", "spec/unit/ldap_spec.rb", "test/common.rb", "test/test_ber.rb", "test/test_entry.rb", "test/test_filter.rb", "test/test_ldif.rb", "test/test_password.rb", "test/test_snmp.rb", "test/testdata.ldif", "testserver/ldapserver.rb", "testserver/testdata.ldif", "test/test_rename.rb"]
  s.homepage = %q{http://net-ldap.rubyforge.org/}
  s.rdoc_options = ["--main", "README.txt"]
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.rubyforge_project = %q{net-ldap}
  s.rubygems_version = %q{1.6.2}
  s.summary = %q{Pure Ruby LDAP support library with most client features and some server features.}
  s.test_files = ["test/test_entry.rb", "test/test_filter.rb", "test/test_ldif.rb", "test/test_password.rb", "test/test_rename.rb", "test/test_snmp.rb"]

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<archive-tar-minitar>, ["~> 0.5.1"])
      s.add_development_dependency(%q<hanna>, ["~> 0.1.2"])
      s.add_development_dependency(%q<hoe-git>, ["~> 1"])
      s.add_development_dependency(%q<metaid>, ["~> 1"])
      s.add_development_dependency(%q<hoe>, [">= 2.8.0"])
    else
      s.add_dependency(%q<archive-tar-minitar>, ["~> 0.5.1"])
      s.add_dependency(%q<hanna>, ["~> 0.1.2"])
      s.add_dependency(%q<hoe-git>, ["~> 1"])
      s.add_dependency(%q<metaid>, ["~> 1"])
      s.add_dependency(%q<hoe>, [">= 2.8.0"])
    end
  else
    s.add_dependency(%q<archive-tar-minitar>, ["~> 0.5.1"])
    s.add_dependency(%q<hanna>, ["~> 0.1.2"])
    s.add_dependency(%q<hoe-git>, ["~> 1"])
    s.add_dependency(%q<metaid>, ["~> 1"])
    s.add_dependency(%q<hoe>, [">= 2.8.0"])
  end
end
