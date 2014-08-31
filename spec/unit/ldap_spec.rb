require 'spec_helper'

describe Net::LDAP do
  describe "initialize" do
    context "when instrumentation is configured" do
      before do
        @connection = flexmock(:connection, :close => true)
        flexmock(Net::LDAP::Connection).should_receive(:new).and_return(@connection)

        @service = MockInstrumentationService.new
      end

      subject do
        Net::LDAP.new \
          :server => "test.mocked.com", :port => 636,
          :instrumentation_service => @service
      end

      it "should instrument bind" do
        events = @service.subscribe "bind.net_ldap"

        # ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
        # ber.ber_identifier = Net::LDAP::PDU::BindResult
        # Net::LDAP::PDU.new([0, ber])
        bind_result = flexmock(:bind_result, :success? => true)
        @connection.should_receive(:bind).with(Hash).and_return(bind_result)

        subject.bind.should be_true

        payload, result = events.pop
        result.should be_true
        payload[:bind].should == bind_result
      end
    end
  end
end

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
      ber.ber_identifier = Net::LDAP::PDU::ModifyResponse
      @tcp_socket.should_receive(:read_ber).and_return([2, ber])

      result = subject.modify(:dn => "1", :operations => [[:replace, "mail", "something@sothsdkf.com"]])
      result.should be_failure
      result.error_message.should == "The provided password value was rejected by a password validator:  The provided password did not contain enough characters from the character set 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.  The minimum number of characters from that set that must be present in user passwords is 1"
    end

    it "shouldn't get back error messages if operation succeeds" do
      ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
      ber.ber_identifier = Net::LDAP::PDU::ModifyResponse
      @tcp_socket.should_receive(:read_ber).and_return([2, ber])

      result = subject.modify(:dn => "1", :operations => [[:replace, "mail", "something@sothsdkf.com"]])
      result.should be_success
      result.error_message.should == ""
    end
  end

  context "instrumentation" do
    before do
      @tcp_socket = flexmock(:connection)
      # handle write
      @tcp_socket.should_receive(:write)
      # return this mock
      flexmock(TCPSocket).should_receive(:new).and_return(@tcp_socket)

      @service = MockInstrumentationService.new
    end

    subject do
      Net::LDAP::Connection.new(:server => 'test.mocked.com', :port => 636,
                                :instrumentation_service => @service)
    end

    it "should publish a write.net_ldap_connection event" do
      ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
      ber.ber_identifier = Net::LDAP::PDU::BindResult
      read_result = [2, ber]
      @tcp_socket.should_receive(:read_ber).and_return(read_result)

      events = @service.subscribe "write.net_ldap_connection"

      result = subject.bind(method: :anon)
      result.should be_success

      # a write event
      payload, result = events.pop
      payload.should have_key(:result)
      payload.should have_key(:content_length)
    end

    it "should publish a read.net_ldap_connection event" do
      ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
      ber.ber_identifier = Net::LDAP::PDU::BindResult
      read_result = [2, ber]
      @tcp_socket.should_receive(:read_ber).and_return(read_result)

      events = @service.subscribe "read.net_ldap_connection"

      result = subject.bind(method: :anon)
      result.should be_success

      # a read event
      payload, result = events.pop
      payload.should have_key(:result)
      result.should == read_result
    end

    it "should publish a search.net_ldap_connection event" do
      # search data
      search_data_ber = Net::BER::BerIdentifiedArray.new([2, [
        "uid=user1,ou=OrgUnit2,ou=OrgUnitTop,dc=openldap,dc=ghe,dc=local",
        [ ["uid", ["user1"]] ]
      ]])
      search_data_ber.ber_identifier = Net::LDAP::PDU::SearchReturnedData
      search_data = [2, search_data_ber]
      # search result (end of results)
      search_result_ber = Net::BER::BerIdentifiedArray.new([0, "", ""])
      search_result_ber.ber_identifier = Net::LDAP::PDU::SearchResult
      search_result = [2, search_result_ber]
      @tcp_socket.should_receive(:read_ber).and_return(search_data).
                                            and_return(search_result)

      events = @service.subscribe "search.net_ldap_connection"

      result = subject.search(filter: "(uid=user1)")
      result.should be_success

      # a search event
      payload, result = events.pop
      payload.should have_key(:result)
      payload.should have_key(:filter)
      payload[:filter].to_s.should == "(uid=user1)"
      result.should be_truthy
    end
  end
end
