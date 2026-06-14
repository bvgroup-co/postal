# frozen_string_literal: true

module API
  module V1
    class DomainsController < BaseController

      rescue_from ActionController::ParameterMissing, with: :render_parameter_missing

      before_action :find_domain, only: [:show, :check, :destroy]

      def create
        domain = current_server.domains.find_by(name: domain_name)
        if domain
          render json: PostalDomainSerializer.new(domain).as_json, status: :ok
          return
        end

        domain = current_server.domains.build(name: domain_name, verification_method: "DNS")

        if domain.save
          render json: PostalDomainSerializer.new(domain).as_json, status: :created
        else
          render_error "InvalidDomain", domain.errors.full_messages.to_sentence, :unprocessable_entity, errors: domain.errors.to_hash
        end
      end

      def show
        render json: PostalDomainSerializer.new(@domain).as_json
      end

      def check
        @domain.verify_with_dns if @domain.verification_method == "DNS"
        @domain.reload
        @domain.check_dns(:manual)
        render json: PostalDomainSerializer.new(@domain).as_json
      end

      def destroy
        @domain.destroy
        head :no_content
      end

      private

      def domain_name
        name = params.require(:name).to_s.strip.downcase.delete_suffix(".")
        if name.blank?
          raise ActionController::ParameterMissing, :name
        end

        name
      end

      def find_domain
        identifier = domain_identifier
        @domain = current_server.domains.find_by(uuid: identifier)
        @domain ||= current_server.domains.find_by(name: identifier.downcase)
        return if @domain

        render_error "DomainNotFound", "Domain was not found.", :not_found
      end

      def domain_identifier
        return "#{params[:domain]}.#{params[:tld]}" if params[:domain] && params[:tld]

        params[:id].to_s
      end

      def render_parameter_missing(exception)
        render_error "ParameterMissing", "#{exception.param} is required.", :bad_request
      end

    end
  end
end
