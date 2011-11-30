require 'spec_helper'

describe Net::LDAP::Connection do
  describe "initialize" do
    context "when host is not responding" do
      before(:each) do
        flexmock(TCPSocket).
          should_receive(:new).and_raise(Errno::ECONNREFUSED)
      end

      it "should raise LdapError" do
        lambda {
          Net::LDAP::Connection.new(
            :server => 'test.mocked.com',
            :port   => 636)
        }.should raise_error(Net::LDAP::LdapError)
      end
    end
    context "when host is blocking the port" do
      before(:each) do
        flexmock(TCPSocket).
          should_receive(:new).and_raise(SocketError)
      end

      it "should raise LdapError" do
        lambda {
          Net::LDAP::Connection.new(
            :server => 'test.mocked.com',
            :port   => 636)
        }.should raise_error(Net::LDAP::LdapError)
      end
    end
    context "on other exceptions" do
      before(:each) do
        flexmock(TCPSocket).
          should_receive(:new).and_raise(NameError)
      end

      it "should rethrow the exception" do
        lambda {
          Net::LDAP::Connection.new(
            :server => 'test.mocked.com',
            :port   => 636)
        }.should raise_error(NameError)
      end
    end
  end

  context "populate error messages" do
    before do
      @tcp_socket = flexmock(:connection)
      @tcp_socket.should_receive(:write)
      flexmock(TCPSocket).should_receive(:new).and_return(@tcp_socket)
    end

    subject { Net::LDAP::Connection.new(:server => 'test.mocked.com', :port => 636) }

    it "should get back error messages if operation fails" do
      ber = Net::BER::BerIdentifiedArray.new([53, "", "The provided password value was rejected by a password validator:  The provided password did not contain enough characters from the character set 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.  The minimum number of characters from that set that must be present in user passwords is 1"])
      ber.ber_identifier = 7
      @tcp_socket.should_receive(:read_ber).and_return([2, ber])

      result = subject.modify(:dn => "1", :operations => [[:replace, "mail", "something@sothsdkf.com"]])
      result.should be_failure
      result.error_message.should == "The provided password value was rejected by a password validator:  The provided password did not contain enough characters from the character set 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.  The minimum number of characters from that set that must be present in user passwords is 1"
    end

    it "shouldn't get back error messages if operation succeeds" do
      ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
      ber.ber_identifier = 7
      @tcp_socket.should_receive(:read_ber).and_return([2, ber])

      result = subject.modify(:dn => "1", :operations => [[:replace, "mail", "something@sothsdkf.com"]])
      result.should be_success
      result.error_message.should == ""
    end
  end
end
