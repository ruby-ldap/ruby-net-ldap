#--
# Net::LDAP for Ruby.
#   http://rubyforge.org/projects/net-ldap/
#   Copyright (C) 2006 by Francis Cianfrocca
#
#   Available under the same terms as Ruby. See LICENCE in the main
#   distribution for full licensing information.
#
# $Id: ChangeLog,v 1.17.2.4 2005/09/09 12:36:42 austin Exp $
#++

spec = Gem::Specification.new do |s|
  s.name              = "ruby-net-ldap"
  s.version           = "0.0.1"
  s.summary           = %q(A pure Ruby LDAP client library.)
  s.platform          = Gem::Platform::RUBY

  s.has_rdoc          = true
  s.rdoc_options      = %w(--title Net::LDAP --main README --line-numbers)
  s.extra_rdoc_files  = %w(README ChangeLog LICENCE COPYING)

  files = %w(README LICENCE ChangeLog COPYING {bin,tests,lib}/**/*)
  s.files             = FileList[*files].exclude("rdoc").to_a

  s.require_paths     = ["lib"]

  s.test_files        = %w{tests/testem.rb}

  s.author            = "Francis Cianfrocca"
  s.email             = "garbagecat10@gmail.com"
  s.rubyforge_project = %q(net-ldap)
  s.homepage          = "http://rubyforge.org/projects/net-ldap"

  description = []
  File.open("README") do |file|
    file.each do |line|
      line.chomp!
      break if line.empty?
      description << "#{line.gsub(/\[\d\]/, '')}"
    end
  end
  s.description = description[1..-1].join(" ")
end
