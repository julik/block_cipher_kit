# Allows an OpenSSL::Cipher to be written through as if it were an IO. This
# allows the cipher to be passed to things like IO.copy_stream
# :nodoc:
class BlockCipherKit::CipherIO
  def initialize(io, cipher)
    @io = io
    @cipher = cipher
  end

  def write(bytes)
    # OpenSSL ciphers fail if you update() them with an empty buffer
    return 0 if bytes.bytesize.zero?

    @io.write(@cipher.update(bytes))
    # We must return the amount of bytes of input
    # we have accepted, not the amount of bytes
    # of output we produced from the cipher
    bytes.bytesize
  end
end
