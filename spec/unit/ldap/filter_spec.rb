require 'spec_helper'

describe Net::LDAP::Filter do
  describe "<- .ex(attr, value)" do
    context "('foo', 'bar')" do
      attr_reader :filter
      before(:each) do
        @filter = Net::LDAP::Filter.ex('foo', 'bar')
      end
      it "should convert to 'foo:=bar'" do
        filter.to_s.should == '(foo:=bar)'
      end 
      it "should survive roundtrip via to_s/from_rfc2254" do
        Net::LDAP::Filter.from_rfc2254(filter.to_s).should == filter
      end 
      it "should survive roundtrip conversion to/from ber" do
        ber = filter.to_ber
        Net::LDAP::Filter.parse_ber(ber.read_ber(Net::LDAP::AsnSyntax)).should ==
          filter
      end 
    end
    context "various legal inputs" do
      [
        '(o:dn:=Ace Industry)', 
        '(:dn:2.4.8.10:=Dino)', 
        '(cn:dn:1.2.3.4.5:=John Smith)', 
        '(sn:dn:2.4.6.8.10:=Barbara Jones)', 
      ].each do |filter_str|
        context "from_rfc2254(#{filter_str.inspect})" do
          attr_reader :filter
          before(:each) do
            @filter = Net::LDAP::Filter.from_rfc2254(filter_str)
          end

          it "should decode into a Net::LDAP::Filter" do
            filter.should be_an_instance_of(Net::LDAP::Filter)
          end 
          it "should survive roundtrip conversion to/from ber" do
            ber = filter.to_ber
            Net::LDAP::Filter.parse_ber(ber.read_ber(Net::LDAP::AsnSyntax)).should ==
              filter
          end 
        end
      end
    end
  end
  
end