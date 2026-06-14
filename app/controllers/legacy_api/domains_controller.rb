# frozen_string_literal: true

module LegacyAPI
  class DomainsController < BaseController

    DNS_RECORD_MX_PRIORITY = 10

    def create
      domain_name = normalize_domain_name(api_params["domain"])
      if domain_name.blank?
        render json: { error: "domain is required" }, status: :unprocessable_entity
        return
      end

      domain = @current_credential.server.domains.build(name: domain_name, verification_method: "DNS")
      if domain.save
        render json: domain_response(domain), status: :created
      else
        render json: { error: domain.errors.full_messages.to_sentence }, status: :unprocessable_entity
      end
    end

    def check
      domain = find_domain
      return if domain.nil?

      domain.verify_with_dns unless domain.verified?
      domain.reload.check_dns(:manual) if domain.reload.verified?

      render json: domain_response(domain.reload)
    end

    def destroy
      domain = find_domain
      return if domain.nil?

      domain.destroy
      head :no_content
    end

    private

    def normalize_domain_name(value)
      return nil unless value.is_a?(String)

      value.strip.downcase
    end

    def find_domain
      domain = @current_credential.server.domains.where("uuid = ? OR id = ?", params[:id], params[:id].to_i).first
      return domain if domain

      render json: { error: "Domain not found" }, status: :not_found
      nil
    end

    def domain_response(domain)
      {
        id: domain.uuid,
        uuid: domain.uuid,
        name: domain.name,
        verified: domain.verified?,
        records: dns_records(domain),
        statuses: dns_statuses(domain)
      }
    end

    def dns_statuses(domain)
      {
        ownership: domain.verified? ? "OK" : "Pending",
        spf: domain.spf_status,
        dkim: domain.dkim_status,
        mx: domain.mx_status,
        return_path: domain.return_path_status,
        checked_at: domain.dns_checked_at&.iso8601
      }
    end

    def dns_records(domain)
      [
        ownership_record(domain),
        spf_record(domain),
        dkim_record(domain),
        return_path_record(domain),
        *mx_records(domain),
      ]
    end

    def ownership_record(domain)
      dns_record(
        type: "TXT",
        host: domain.name,
        value: domain.dns_verification_string,
        purpose: "ownership-verification",
        required: true,
        status: domain.verified? ? "OK" : "Pending"
      )
    end

    def spf_record(domain)
      dns_record(
        type: "TXT",
        host: domain.name,
        value: domain.spf_record,
        purpose: "spf",
        required: true,
        status: domain.spf_status,
        error: domain.spf_error
      )
    end

    def dkim_record(domain)
      dns_record(
        type: "TXT",
        host: "#{domain.dkim_record_name}.#{domain.name}",
        value: domain.dkim_record,
        purpose: "dkim",
        required: true,
        status: domain.dkim_status,
        error: domain.dkim_error
      )
    end

    def return_path_record(domain)
      dns_record(
        type: "CNAME",
        host: domain.return_path_domain,
        value: Postal::Config.dns.return_path_domain,
        purpose: "return-path",
        required: false,
        status: domain.return_path_status,
        error: domain.return_path_error
      )
    end

    def mx_records(domain)
      Postal::Config.dns.mx_records.map do |mx_record|
        dns_record(
          type: "MX",
          host: domain.name,
          value: mx_record,
          purpose: "inbound-mx",
          required: false,
          status: domain.mx_status,
          error: domain.mx_error,
          priority: DNS_RECORD_MX_PRIORITY
        )
      end
    end

    def dns_record(type:, host:, value:, purpose:, required:, status: nil, error: nil, priority: nil)
      record = {
        type: type,
        host: host,
        value: value,
        purpose: purpose,
        required: required,
        status: status,
        error: error
      }
      record[:priority] = priority if priority
      record
    end

  end
end
