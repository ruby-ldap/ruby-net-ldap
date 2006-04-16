# $Id$
# Rakefile for the netldap ruby gem.
#


require 'rubygems'
Gem::manage_gems
require 'rake/gempackagetask'

em_version = "0.0.1"

spec = Gem::Specification.new {|s|
	s.name = "netldap"
	s.version = em_version
	s.author = "Francis Cianfrocca"
	s.email = "garbagecat10@gmail.com"
	s.homepage = "netldap@rubyforge.org"
	s.summary = "Net::LDAP library"
	s.files = FileList["{bin,tests,lib}/**/*"].exclude("rdoc").to_a
	s.require_paths = ["lib"]
	s.test_file = "tests/testem.rb"
	s.has_rdoc = true
	s.extra_rdoc_files = ["README", "RELEASE_NOTES", "COPYING"]
}

Rake::GemPackageTask.new( spec ) {|pkg|
	pkg.need_tar = true
}


task :default => ["pkg/netldap-#{em_version}.gem"]

