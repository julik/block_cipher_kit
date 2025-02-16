require "forwardable"

# Allows a string with key material (like IV and key)
# to be concealed when an object holding it gets printed or show via #inspect
# :nodoc:
class BlockCipherKit::KeyMaterial
  extend Forwardable
  def_delegators :@str, :b, :byteslice, :to_s, :to_str

  def initialize(str)
    @str = str
  end

  def inspect
    "[SENSITIVE(#{@str.bytesize * 8} bits)]"
  end
end
