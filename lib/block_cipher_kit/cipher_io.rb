# Allows an OpenSSL::Cipher to be written through as if it were an IO. This
# allows the cipher to be passed to things like IO.copy_stream
class BlockCipherKit::CipherIO
  def initialize(io, cipher)
    @io = io
    @cipher = cipher
  end

  def write(bytes)
    @io.write(@cipher.update(bytes))
    # We must return the amount of bytes of input
    # we have accepted, not the amount of bytes
    # of output we produced from the cipher
    bytes.bytesize
  end
end
