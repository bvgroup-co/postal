# frozen_string_literal: true

module API
  module V1
    class BaseController < ActionController::Base

      skip_before_action :set_browser_id
      skip_before_action :validate_auth_session
      skip_before_action :verify_authenticity_token
      skip_around_action :touch_auth_session

      before_action :authenticate_as_server

      private

      def current_server
        @current_credential.server
      end

      def authenticate_as_server
        key = request.headers["X-Server-API-Key"]
        if key.blank?
          render_error "AccessDenied", "Must be authenticated as a server.", :unauthorized
          return
        end

        credential = Credential.where(type: "API", key: key).first
        if credential.nil?
          render_error "InvalidServerAPIKey", "The API token provided in X-Server-API-Key was not valid.", :unauthorized
          return
        end

        if credential.server.suspended?
          render_error "ServerSuspended", "The server for this API token is suspended.", :forbidden
          return
        end

        credential.use
        @current_credential = credential
      end

      def render_error(code, message, status, details = {})
        render json: {
          status: "error",
          error: details.merge(
            code: code,
            message: message
          )
        }, status: status
      end

    end
  end
end
