# frozen_string_literal: true

require_relative "test_helper"

class KeyMaterialTest < Minitest::Test
  def test_conceals_but_provides_string_access
    km = BlockCipherKit::KeyMaterial.new("foo")
    assert_equal "[SENSITIVE(24 bits)]", km.inspect
    assert_equal "foo", [km].join
    assert_equal "foo".b, km.b
  end
end
