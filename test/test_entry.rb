require 'common'

class TestEntry < Test::Unit::TestCase
  def setup
    @entry = Net::LDAP::Entry.new 'cn=Barbara,o=corp'
  end

  def test_dn
    assert_equal 'cn=Barbara,o=corp', @entry.dn
  end

  def test_empty_array_when_accessing_nonexistent_attribute
    assert_equal [], @entry['sn']
  end

  def test_empty_attribute_by_method
    skip "Net::LDAP::Entry#valid_attribute? requires an attribute to be defined first"
    # What is the valid encoding for attribute names?
    assert_equal [], @entry.sn
  end

  def test_attribute_assignment
    @entry['sn'] = 'Jensen'
    assert_equal ['Jensen'], @entry['sn']
    assert_equal ['Jensen'], @entry.sn
    assert_equal ['Jensen'], @entry[:sn]

    @entry[:sn] = 'Jensen'
    assert_equal ['Jensen'], @entry['sn']
    assert_equal ['Jensen'], @entry.sn
    assert_equal ['Jensen'], @entry[:sn]

    @entry.sn = 'Jensen'
    assert_equal ['Jensen'], @entry['sn']
    assert_equal ['Jensen'], @entry.sn
    assert_equal ['Jensen'], @entry[:sn]
  end

  def test_case_insensitive_attribute_names
    @entry['sn'] = 'Jensen'
    assert_equal ['Jensen'], @entry.sn
    assert_equal ['Jensen'], @entry.Sn
    assert_equal ['Jensen'], @entry.SN
    assert_equal ['Jensen'], @entry['sn']
    assert_equal ['Jensen'], @entry['Sn']
    assert_equal ['Jensen'], @entry['SN']
  end
end
