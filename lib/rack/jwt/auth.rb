require "rack/jwt/auth/version"
require "jwt"
require "jwe"
require "loga"
require "rack/jwt/auth/auth_token"
require "rack/jwt/auth/authenticate"

# Loga initialization based on previous
# configuration if existing or rescue error
# to provide new configuration
begin 
  config = Loga.configuration
  config.service_name = "RACK_JWT_AUTH"
rescue Loga::ConfigurationError
  Loga.configure(
    filter_parameters: [:password],
    level: ENV["LOG_LEVEL"] || "DEBUG",
    format: :gelf,
    service_name: "RACK_JWT_AUTH",
    tags: [:uuid]
  )
end
