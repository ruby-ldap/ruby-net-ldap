# -*- ruby encoding: utf-8 -*-

require "rubygems"
require 'hoe'

Hoe.plugin :doofus
Hoe.plugin :git
Hoe.plugin :gemspec

Hoe.spec 'net-ldap' do
  self.rubyforge_name = 'net-ldap'

  self.developer("Francis Cianfrocca", "blackhedd@rubyforge.org")
  self.developer("Emiel van de Laar", "gemiel@gmail.com")
  self.developer("Rory O'Connell", "rory.ocon@gmail.com")
  self.developer("Kaspar Schiess", "kaspar.schiess@absurd.li")
  self.developer("Austin Ziegler", "austin@rubyforge.org")

  self.remote_rdoc_dir = ''
  self.rsync_args << ' --exclude=statsvn/'

  self.url = %W(http://net-ldap.rubyforge.org/ https://github.com/ruby-ldap/ruby-net-ldap)

  self.history_file = 'History.rdoc'
  self.readme_file = 'README.rdoc'

  self.extra_rdoc_files = FileList["*.rdoc"].to_a

  self.extra_dev_deps << [ "hoe-git", "~> 1" ]
  self.extra_dev_deps << [ "hoe-gemspec", "~> 1" ]
  self.extra_dev_deps << [ "metaid", "~> 1" ]
  self.extra_dev_deps << [ "flexmock", "~> 0.9.0" ]
  self.extra_dev_deps << [ "rspec", "~> 2.0" ]

  self.clean_globs << "coverage"

  self.spec_extras[:required_ruby_version] = ">= 1.8.7"
  self.multiruby_skip << "1.8.6"
  self.multiruby_skip << "1_8_6"

  self.need_tar = true
end

# I'm not quite ready to get rid of this, but I think "rake git:manifest" is
# sufficient.
namespace :old do
  desc "Build the manifest file from the current set of files."
  task :build_manifest do |t|
    require 'find'

    paths = []
    Find.find(".") do |path|
      next if File.directory?(path)
      next if path =~ /\.svn/
        next if path =~ /\.git/
        next if path =~ /\.hoerc/
        next if path =~ /\.swp$/
        next if path =~ %r{coverage/}
      next if path =~ /~$/
        paths << path.sub(%r{^\./}, '')
    end

    File.open("Manifest.txt", "w") do |f|
      f.puts paths.sort.join("\n")
    end

    puts paths.sort.join("\n")
  end
end

desc "Run a full set of integration and unit tests" 
task :cruise => [:test, :spec]

# vim: syntax=ruby
