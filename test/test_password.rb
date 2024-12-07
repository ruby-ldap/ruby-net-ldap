# $Id: testpsw.rb 72 2006-04-24 21:58:14Z blackhedd $

require_relative 'test_helper'

class TestPassword < Test::Unit::TestCase
  def test_psw
    assert_equal("{MD5}xq8jwrcfibi0sZdZYNkSng==", Net::LDAP::Password.generate(:md5, "cashflow"))
    assert_equal("{SHA}YE4eGkN4BvwNN1f5R7CZz0kFn14=", Net::LDAP::Password.generate(:sha, "cashflow"))
  end

  def test_psw_with_ssha256_should_not_contain_linefeed
    flexmock(SecureRandom).should_receive(:random_bytes).and_return('\xE5\x8A\x99\xF8\xCB\x15GW\xE8\xEA\xAD\x0F\xBF\x95\xB0\xDC')
    assert_equal("{SSHA256}Cc7MXboTyUP5PnPAeJeCrgMy8+7Gus0sw7kBJuTrmf1ceEU1XHg4QVx4OTlceEY4XHhDQlx4MTVHV1x4RThceEVBXHhBRFx4MEZceEJGXHg5NVx4QjBceERD", Net::LDAP::Password.generate(:ssha256, "cashflow"))
  end
end
