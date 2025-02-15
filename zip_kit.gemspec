lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "block_cipher_kit/version"

Gem::Specification.new do |spec|
  spec.name = "block_cipher_kit"
  spec.version = BlockCipherKit::VERSION
  spec.authors = ["Julik Tarkhanov", "Sebastian van Hesteren"]
  spec.email = ["me@julik.nl"]
  spec.license = "MIT"
  spec.summary = "A thin toolkit for working with block cipher encryption."
  spec.description = "A thin toolkit for working with block cipher encryption."
  spec.homepage = "https://github.com/julik/block_cipher_kit"

  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.files = `git ls-files -z`.split("\x0")
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "openssl"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "minitest"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "magic_frozen_string_literal"
  spec.add_development_dependency "standard", "1.28.5" # Needed for 2.6
  spec.add_development_dependency "yard"
  # redcarpet is needed for the yard gem to enable Github Flavored Markdown
  spec.add_development_dependency "redcarpet"
  spec.add_development_dependency "sord"
end
