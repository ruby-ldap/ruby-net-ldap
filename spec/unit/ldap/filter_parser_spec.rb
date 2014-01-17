# encoding: utf-8
require 'spec_helper'

describe Net::LDAP::Filter::FilterParser do

  describe "#parse" do
    context "Given ASCIIs as filter string" do
      let(:filter_string) { "(cn=name)" }
      specify "should generate filter object" do
        expect(Net::LDAP::Filter::FilterParser.parse(filter_string)).to be_a Net::LDAP::Filter
      end
    end
    context "Given string including multibyte chars as filter string" do
      let(:filter_string) { "(cn=名前)" }
      specify "should generate filter object" do
        expect(Net::LDAP::Filter::FilterParser.parse(filter_string)).to be_a Net::LDAP::Filter
      end
    end
  end
end
