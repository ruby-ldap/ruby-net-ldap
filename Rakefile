require "rubygems"
require 'hoe'

$LOAD_PATH.unshift('lib')

require 'net/ldap'

PKG_NAME    = 'net-ldap'
PKG_VERSION = Net::LDAP::VERSION
PKG_DIST    = "#{PKG_NAME}-#{PKG_VERSION}"
MANIFEST    = File.read("Manifest.txt").split
MINRUBY     = "1.8.7"

Hoe.plugin :git
Hoe.plugin :gemspec

Hoe.spec PKG_NAME do
  self.version = PKG_VERSION
  self.rubyforge_name = PKG_NAME

  developer "Francis Cianfrocca", "blackhedd@rubyforge.org"
  developer "Emiel van de Laar", "gemiel@gmail.com"
  developer "Rory O'Connell", "rory.ocon@gmail.com"
  developer "Kaspar Schiess", "kaspar.schiess@absurd.li"
  developer "Austin Ziegler", "austin@rubyforge.org" 

  self.remote_rdoc_dir = ''
  rsync_args << ' --exclude=statsvn/'

  self.url = %W(http://net-ldap.rubyforge.org/ https://github.com/RoryO/ruby-net-ldap)

  self.summary = "Pure Ruby LDAP support library with most client features and some server features."
  self.changes = paragraphs_of(self.history_file, 0..1).join("\n\n")
  self.description = paragraphs_of(self.readme_file, 2..2).join("\n\n")

  extra_rdoc_files << "Hacking.rdoc"

  extra_dev_deps << [ "hoe-git", "~> 1" ]
  extra_dev_deps << [ "hoe-gemspec", "~> 1" ]
  extra_dev_deps << [ "metaid", "~> 1" ]
  extra_dev_deps << [ "flexmock", "~> 0.9.0" ]
  extra_dev_deps << [ "rspec", "~> 2.0" ]
  clean_globs << "coverage"

  spec_extras[:required_ruby_version] = ">= #{MINRUBY}"
  multiruby_skip << "1.8.6"
  multiruby_skip << "1_8_6"

  self.need_tar = true
end

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

desc "Run a full set of integration and unit tests" 
task :cruise => [:test, :spec]
