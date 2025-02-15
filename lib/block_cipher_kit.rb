begin
  require "openssl"
rescue LoadError
  message = <<~ERR
    
    Unable to load "openssl". You may be running a version of Ruby where the "openssl"
    library is not contained in the standard library, but must be installed as a gem.
    
    We do not specify "openssl" as a dependency of block_cipher_kit because gems spun off
    from the standard library can cause problems if they are specified as transitive dependencies,
    especially on older Ruby versions.

    Running `bundle add openssl` in your application will likely resolve the issue.
  ERR
  raise LoadError, message
end

require "securerandom"
module BlockCipherKit
  autoload :IOLens, __dir__ + "/block_cipher_kit/io_lens.rb"
  autoload :BlockWritable, __dir__ + "/block_cipher_kit/block_writable.rb"
  autoload :CipherIO, __dir__ + "/block_cipher_kit/cipher_io.rb"
  autoload :KeyMaterial, __dir__ + "/block_cipher_kit/key_material.rb"
  autoload :BaseScheme, __dir__ + "/block_cipher_kit/base_scheme.rb"
  autoload :PassthruScheme, __dir__ + "/block_cipher_kit/passthru_scheme.rb"
  autoload :AES256CTRScheme, __dir__ + "/block_cipher_kit/aes_256_ctr_scheme.rb"
  autoload :AES256CBCScheme, __dir__ + "/block_cipher_kit/aes_256_cbc_scheme.rb"
  autoload :AES256GCMScheme, __dir__ + "/block_cipher_kit/aes_256_gcm_scheme.rb"
  autoload :AES256CFBScheme, __dir__ + "/block_cipher_kit/aes_256_cfb_scheme.rb"
  autoload :AES256CFBCIVScheme, __dir__ + "/block_cipher_kit/aes_256_cfb_civ_scheme.rb"
  autoload :EncryptedDiskService, __dir__ + "/block_cipher_kit/encrypted_disk_service.rb"
end
