module Rack
  module Jwt
    module Auth

      module AuthToken

        def self.issue_token(payload, secret, key = nil)
          token = JWT.encode(payload, secret)
          key ? JWE.encrypt(token, key, alg: 'dir', enc: 'A128CBC-HS256') : token
        end

        def self.valid?(token, secret, key = nil)
          p "T1 " + token
          p "Secret " + secret
          p "Key " + key
          begin
            token = JWE.decrypt(token, key) if key
            p "T2 " + token
            p JWT.decode(token, secret)[0]
            JWT.decode(token, secret)
          rescue => error
            p error
            false
          end
        end

      end

    end
  end
end
