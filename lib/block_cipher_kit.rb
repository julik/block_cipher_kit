require "openssl"

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
  autoload :EncryptedDiskService, __dir__ + "/block_cipher_kit/encrypted_disk_service.rb"
end
