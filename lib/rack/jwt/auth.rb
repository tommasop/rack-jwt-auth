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
  Loga.configuration.service_name = "RACK_JWT_AUTH"
  Loga.logger.formatter = Loga.configuration.send(:assign_formatter)
rescue Loga::ConfigurationError
  Loga.configure(
    filter_parameters: [:password],
    level: ENV["LOG_LEVEL"] || "DEBUG",
    format: :gelf,
    service_name: "RACK_JWT_AUTH",
    tags: [:uuid]
  )
end
