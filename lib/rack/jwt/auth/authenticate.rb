module Rack
  module Jwt
    module Auth

      class Authenticate

        def initialize(app, opts = {})
          @app  = app
          @opts = opts

          raise 'Secret must be provided' if opts[:jwt_secret].nil?

          @secret = opts[:jwt_secret]
          @key = opts[:jwe_key]

          @authenticated_routes   = compile_paths(opts[:only])
          @unauthenticated_routes = compile_paths(opts[:except])
          @encrypted_routes = compile_paths(opts[:encrypt])
        end
        
        def call(env)
          with_authorization(env) do |payload|
            if payload.class == Array
              payload.map!{|tk| tk.class == String ? tk : tk.to_json } 
              to_be_stored, to_be_stored_ext = payload
            else
              to_be_stored = payload.class == String ? payload : payload.to_json
            end
            
            if to_be_stored_ext
              env['rack.jwt.session'] = to_be_stored
              env['rack.jwt.ext.session'] = to_be_stored_ext
            else
              env['rack.jwt.session'] = to_be_stored
            end

            @app.call(env)
          end
        end

        private

        def authenticated_route?(env)
          if @authenticated_routes.length > 0
            @authenticated_routes.find { |route| route =~ env['PATH_INFO'] }
          else
            !@unauthenticated_routes.find { |route| route =~ env['PATH_INFO'] }
          end
        end

        def encrypted_route?(env)
          @encrypted_routes.find { |route| route =~ env['PATH_INFO'] } if @encrypted_routes.length > 0
        end

        def with_authorization(env)
          if authenticated_route?(env)
            header  = env['HTTP_AUTHORIZATION']

            return [401, {}, [{message: 'Missing Authorization header'}.to_json]] if header.nil?

            scheme, token = header.split(" ")

            return [401, {}, [{message: 'Format is Authorization: Bearer [token]'}.to_json]] unless scheme.match(/^Bearer$/i) && !token.nil?

            if encrypted_route?(env)
              payload = AuthToken.valid?(token, @secret, @key)
            else
              payload = AuthToken.valid?(token, @secret)
            end

            p "Payload " + payload

            return [401, {}, [{message: 'Invalid Authorization'}.to_json]] unless payload
            
            if payload[0]
              # I take into account the situation where I have another token
              # folded into the external one
              if payload[0]["external_token"]
                if encrypted_route?(env)
                  ext_payload = AuthToken.valid?(payload[0]["external_token"], @secret, @key)
                else
                  ext_payload = AuthToken.valid?(payload[0]["external_token"], @secret) 
                end
                ext_payload = ext_payload[0] if ext_payload[0]
              end

              payload = ext_payload ? [ext_payload, payload[0]] : payload[0]
            end
          end
          
          yield payload
        end

        def compile_paths(paths)
          return [] if paths.nil?

          paths.map do |path|
            compile(path)
          end
        end

        def compile(path)
          if path.respond_to? :to_str
            special_chars = %w{. + ( )}
            pattern =
              path.to_str.gsub(/((:\w+)|[\*#{special_chars.join}])/) do |match|
                case match
                when "*"
                  "(.*?)"
                when *special_chars
                  Regexp.escape(match)
                else
                  "([^/?&#]+)"
                end
              end
            /^#{pattern}$/
          elsif path.respond_to? :match
            path
          else
            raise TypeError, path
          end
        end
      end

    end
  end
end
