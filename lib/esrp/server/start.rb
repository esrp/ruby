# frozen_string_literal: true

module ESRP
  class Server

    ##
    # Class: Host auth, Step 1
    #
    # Create a challenge for the client, and a proof to be stored
    # on the server for later use when verifying the client response.
    #
    #   # Client -> Server: username, A
    #   user = DB[:users].where(username: params[:username]).first
    #   start = ESRP::Server::Start.new(engine, user, params[:A])
    #
    #   # Server stores proof to session
    #   session[:proof] = start.proof
    #
    #   # Server -> Client: B, salt
    #   start.challenge
    #
    class Start
      def initialize(engine, user, aa)
        @engine = engine
        @user = Utils.symbolize_keys(user)
        @A = aa

        validate_params!

        @b = generate_b
      end

      def b
        @b ||= engine.crypto.random
      end
    end
  end
end
