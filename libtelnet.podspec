Pod::Spec.new do |s|
  s.name         = "libtelnet"
  s.version      = "0.21"
  s.summary      = "Simple RFC-complient TELNET implementation as a C library."
  s.license      = "Public Domain"
  s.homepage     = "http://github.com/seanmiddleditch/libtelnet"

  s.author       = { "Sean Middleditch" => "sean@seanmiddleditch.com" }

  s.ios.deployment_target = "7.0"
  
  s.source       = { :git => "https://github.com/jhersh/libtelnet.git" }
  s.source_files = "libtelnet.{h,c}"
  s.public_header_files = "libtelnet.h"
  
  s.library = "z"
  s.compiler_flags = "-DHAVE_ZLIB"
  s.requires_arc = false
end
