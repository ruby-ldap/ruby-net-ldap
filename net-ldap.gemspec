spec = Gem::Specification.new {|s|
	s.name = "netldap"
	s.version = "0.0.1"
	s.author = "Francis Cianfrocca"
	s.email = "garbagecat10@gmail.com"
	s.homepage = "netldap@rubyforge.org"
	s.summary = "Net::LDAP library"
	s.files = FileList["{bin,tests,lib}/**/*"].exclude("rdoc").to_a
	s.require_paths = ["lib"]
	s.test_file = "tests/testem.rb"
	s.has_rdoc = true
	s.extra_rdoc_files = ["README", "ChangeLog", "LICENCE"]
}
