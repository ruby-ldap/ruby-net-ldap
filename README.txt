= Net::LDAP for Ruby

== Description

Net::LDAP for Ruby (also called "net-ldap") is a pure-Ruby LDAP support
library that has been tested against several modern servers, including
OpenLDAP and Active Directory. It supports most LDAP client features and
a subset of server features.

LDAP (Lightweight Directory Access Protocol) is an Internet protocol for
accessing distributed directory services. LDAP is often used to provide
access and authentication to networked services.

The current release is mostly compliant with RFCs 2251–2256, 2829–2830,
3377, and 3771. Our roadmap for Net::LDAP 1.0 is to gain full
<em>client</em> compliance with the most recent IETF LDAP RFCs
(4510–4519, plus portions of 4520–4532).

=== Notice of Impending License Change

In the next release of Net::LDAP (0.3), we will be changing the license
to an MIT-style license.

== Where

* RubyForge: net-ldap[http://rubyforge.org/projects/net-ldap]
* GitHub: RoryO/ruby-net-ldap[http://github.com/RoryO/ruby-net-ldap/]
* Group: ruby-ldap[http://groups.google.com/group/ruby-ldap]
* Documentation: net-ldap[http://net-ldap.rubyforge.org/]

== Requirements

Net::LDAP requires Ruby 1.8.7-compliant interpreter or better.

== Install

Net::LDAP is a pure Ruby library. It does not require any external
compiled libraries.

You can install the RubyGems version of Net::LDAP available from the usual
sources.

  gem install net-ldap

Simply require either 'net-ldap' or 'net/ldap'.

For non-RubyGems installations of Net::LDAP, you can use Minero Aoki's
{setup.rb}[http://i.loveruby.net/en/projects/setup/] as the layout of
Net::LDAP is compliant. The setup installer is not included in the
Net::LDAP repository.

== Credits

Net::LDAP was originally developed by:

* Francis Cianfrocca blackhedd@rubyforge.org

Contributions since:

* Emiel van de Laar emiel@rubyforge.org
* Rory O'Connell roryo@rubyforge.org
* Kaspar Schiess eule@rubyforge.org
* Austin Ziegler austin@rubyforge.org
* Dimitrij Denissenko dimdenis@rubyforge.org
* "nowhereman" on GitHub

== License

Copyright (C) 2006 - 2010 by Francis Cianfrocca and other contributors.

Please read the file LICENSE for licensing restrictions on this library.
In the simplest terms, this library is available under the same terms as
Ruby itself.

Available under the same terms as Ruby. See LICENSE in the main
distribution for full licensing information.
