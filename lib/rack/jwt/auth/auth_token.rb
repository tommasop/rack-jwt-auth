module Rack
  module Jwt
    module Auth

      module AuthToken

        def self.issue_token(payload, secret, key = nil)
          token = JWT.encode(payload, secret)
          key ? JWE.encrypt(token, key, alg: 'dir') : token
        end

        def self.valid?(token, secret, key = nil)
          begin
            token = JWE.decrypt(token, key) if key
            JWT.decode(token, secret)
          rescue
            false
          end
        end

      end

    end
  end
end
