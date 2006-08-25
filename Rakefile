#! /usr/bin/env rake
#--
# Net::LDAP for Ruby.
#   http://rubyforge.org/projects/net-ldap/
#   Copyright (C) 2006 by Francis Cianfrocca
#
#   Available under the same terms as Ruby. See LICENCE in the main
#   distribution for full licensing information.
#
# $Id$
#++

require 'meta_project'
require 'rake/gempackagetask'
require 'rake/contrib/xforge'
require 'rake/clean'

$can_gmail = false
begin
  require 'gmailer'
  $can_gmail = true
rescue LoadError
end

$can_minitar = false
begin
  require 'archive/tar/minitar'
  require 'zlib'
  $can_minitar  = true
rescue LoadError
end

$LOAD_PATH.unshift "lib"
require 'net/ldap'

$version  = Net::LDAP::VERSION
$name     = Net::LDAP.to_s
$project  = MetaProject::Project::XForge::RubyForge.new('net-ldap')
$distdir  = "ruby-net-ldap-#$version"
$tardist  = "../#$distdir.tar.gz"

$release_date = nil
$release_date = Time.parse(ENV['RELEASE_DATE']) if ENV['RELEASE_DATE']

desc "Run the tests for #$name."
task :test do |t|
  require 'test/unit/testsuite'
  require 'test/unit/ui/console/testrunner'

  runner = Test::Unit::UI::Console::TestRunner

  $LOAD_PATH.unshift('tests')
  $stderr.puts "Checking for test cases:" if t.verbose
  Dir['tests/test*.rb'].each do |testcase|
    $stderr.puts "\t#{testcase}" if t.verbose
    load testcase
  end

  suite = Test::Unit::TestSuite.new($name)

  ObjectSpace.each_object(Class) do |testcase|
    suite << testcase.suite if testcase < Test::Unit::TestCase
  end

  runner.run(suite)
end

spec = eval(File.read("net-ldap.gemspec"))
spec.version = $version
desc "Build the RubyGem for #$name."
task :gem => [ :test ]
Rake::GemPackageTask.new(spec) do |g|
  if $can_minitar
    g.need_tar    = false
    g.need_zip    = false
  end
  g.package_dir = ".."
end

if $can_minitar
  desc "Build a #$name .tar.gz distribution."
  task :tar => [ $tardist ]
  file $tardist => [ :test ] do |t|
    current = File.basename(Dir.pwd)
    Dir.chdir("..") do
      begin
        files = %W(bin/**/* lib/**/* tests/**/* ChangeLog README LICENCE
                 COPYING Rakefile net-ldap.gemspec setup.rb pre-setup.rb)
        files = FileList[files.map { |file| File.join(current, file) }].to_a
        files.map! do |dd|
          ddnew = dd.gsub(/^#{current}/, $distdir)
          mtime = $release_date || File.stat(dd).mtime
          if File.directory?(dd)
            { :name => ddnew, :mode => 0755, :dir => true, :mtime => mtime }
          else
            if dd =~ %r{bin/}
              mode = 0755
            else
              mode = 0644
            end
            data = File.open(dd, "rb") { |ff| ff.read }
            { :name => ddnew, :mode => mode, :data => data, :size =>
              data.size, :mtime => mtime }
          end
        end

        ff = File.open(t.name.gsub(%r{^\.\./}o, ''), "wb")
        gz = Zlib::GzipWriter.new(ff)
        tw = Archive::Tar::Minitar::Writer.new(gz)

        files.each do |entry|
          if entry[:dir]
            tw.mkdir(entry[:name], entry)
          else
            tw.add_file_simple(entry[:name], entry) { |os| os.write(entry[:data]) }
          end
        end
      ensure
        tw.close if tw
        gz.finish if gz
        ff.close
      end
    end
  end
  task $tardist => [ :test ]
end

desc "Build the RDoc documentation for #$name."
task :docs do
  require 'rdoc/rdoc'
  rdoc_options = %W(--title #$name --main README --line-numbers)
  files = FileList[*%w(README LICENCE ChangeLog LICENCE bin/**/*.rb lib/**/*.rb)]
  rdoc_options += files.to_a
  RDoc::RDoc.new.document(rdoc_options)
end

task :verify_rubyforge do
  raise "RUBYFORGE_USER environment variable not set!" unless ENV['RUBYFORGE_USER']
  raise "RUBYFORGE_PASSWORD environment variable not set!" unless ENV['RUBYFORGE_PASSWORD']
end

if $can_gmail
  task :verify_gmail do
    raise "GMAIL_USER environment variable not set!" unless ENV['GMAIL_USER']
    raise "GMAIL_PASSWORD environment variable not set!" unless ENV['GMAIL_PASSWORD']
  end

  desc "Post a release announcement via GMail."
  task :email_announcement => [ :verify_gmail ] do
    GMailer.connect(ENV["GMAIL_USER"], ENV["GMAIL_PASSWORD"]) do |gmail|
      msg = {
        :to       => "ruby-talk@ruby-lang.org, #{ENV['GMAIL_USER']}@gmail.com",
        :subject  => "[ANN] #$name #$version",
        :body     => File.read("Release-Announcement"),
      }
      gmail.send msg
    end
  end
end

desc "Release files on RubyForge."
task :release_files => [ :verify_rubyforge, :gem ] do
  release_files = FileList[$tardist, "../#$distdir.gem"]
  Rake::XForge::Release.new($project) do |release|
    release.user_name     = ENV['RUBYFORGE_USER']
    release.password      = ENV['RUBYFORGE_PASSWORD']
    release.files         = release_files.to_a
    release.release_name  = "#$name #$version"
    release.package_name  = "ruby-net-ldap"

    notes = []
    File.open("README") do |file|
      file.each do |line|
        line.chomp!
        line.gsub!(/^#.*$/, '') and next
        notes << line
      end
    end
    release.release_notes   = notes.join("\n")

    changes = []
    File.open("ChangeLog") do |file|
      current = true

      file.each do |line|
        line.chomp!
        current = false if current and line =~ /^==/
        break if line.empty? and not current
        changes << line
      end
    end
    release.release_changes = changes.join("\n")
  end
end

desc "Publish news on RubyForge"
task :publish_news => [ :verify_rubyforge, :gem ] do
  Rake::XForge::NewsPublisher.new($project) do |news|
    news.user_name    = ENV['RUBYFORGE_USER']
    news.password     = ENV['RUBYFORGE_PASSWORD']
    news.subject      = "#$name #$version Released"
    news.changes_file = nil

    details = []
    File.open("Release-Announcement") do |file|
      file.each do |line|
        line.chomp!
        break if line =~ /^=/
        details << line
      end
    end
    news.details      = details.join("\n")
  end
end

desc "Release the latest version."
task :release => [ :verify_rubyforge, :release_files, :publish_news, :docs ]
if $can_gmail
  task :release => [ :verify_gmail, :email_announcment ]
end

desc "Build everything."
task :default => [ :gem ]

if $can_minitar
  task :release_files => :tar
  task :publish_news => :tar
  task :default => :tar
end
