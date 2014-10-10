require 'spec_helper'
require 'metaid'

describe Array, "when extended with BER core extensions" do

  it "should correctly convert a control code array" do
    control_codes = []
    control_codes << ['1.2.3'.to_ber, true.to_ber].to_ber_sequence
    control_codes << ['1.7.9'.to_ber, false.to_ber].to_ber_sequence
    control_codes = control_codes.to_ber_sequence
    res = [['1.2.3', true],['1.7.9',false]].to_ber_control
    res.should eq(control_codes)
  end

  it "should wrap the array in another array if a nested array is not passed" do
    result1 = ['1.2.3', true].to_ber_control
    result2 = [['1.2.3', true]].to_ber_control
    result1.should eq(result2)
  end

  it "should return an empty string if an empty array is passed" do
    [].to_ber_control.should be_empty
  end
end
