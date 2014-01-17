# -*- ruby encoding: utf-8 -*-

describe Net::LDAP, "search method" do
  class FakeConnection
    def search(args)
      OpenStruct.new(:result_code => 1, :message => "error", :success? => false)
    end
  end

  before(:each) do
    @connection = Net::LDAP.new
    @connection.instance_variable_set(:@open_connection, FakeConnection.new)
  end

  context "when :return_result => true" do
    it "should return nil upon error" do
      result_set = @connection.search(:return_result => true)
      result_set.should be_nil
    end
  end

  context "when :return_result => false" do
    it "should return false upon error" do
      result = @connection.search(:return_result => false)
      result.should be_false
    end
  end

  context "When :return_result is not given" do
    it "should return nil upon error" do
      result_set = @connection.search
      result_set.should be_nil
    end
  end
end
