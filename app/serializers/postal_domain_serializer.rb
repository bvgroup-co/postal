# frozen_string_literal: true

class PostalDomainSerializer

  DNS_PURPOSES = {
    verification: "ownership-verification",
    spf: "spf",
    dkim: "dkim",
    mx: "inbound-mx",
    return_path: "return-path"
  }.freeze

  MX_PRIORITY = 10
  OPTIONAL_PURPOSES = [DNS_PURPOSES[:mx], DNS_PURPOSES[:return_path]].freeze

  def initialize(domain)
    @domain = domain
  end

  def as_json(*)
    {
      id: @domain.uuid,
      uuid: @domain.uuid,
      name: @domain.name,
      verified: @domain.verified?,
      dns_ok: @domain.dns_ok?,
      dns_checked_at: @domain.dns_checked_at&.iso8601,
      records: records,
      statuses: statuses
    }
  end

  private

  def records
    [
      verification_record,
      spf_record,
      dkim_record,
      return_path_record,
      mx_records,
    ].flatten.compact
  end

  def statuses
    {
      verification: verification_status,
      spf: status_for(:spf),
      dkim: status_for(:dkim),
      mx: status_for(:mx),
      return_path: status_for(:return_path)
    }
  end

  def verification_record
    record(
      "TXT",
      @domain.name,
      @domain.dns_verification_string,
      DNS_PURPOSES[:verification],
      status: verification_status[:status],
      error: verification_status[:error]
    )
  end

  def spf_record
    record(
      "TXT",
      @domain.name,
      @domain.spf_record,
      DNS_PURPOSES[:spf],
      status: @domain.spf_status,
      error: @domain.spf_error
    )
  end

  def dkim_record
    record(
      "TXT",
      @domain.dkim_record_name,
      @domain.dkim_record,
      DNS_PURPOSES[:dkim],
      status: @domain.dkim_status,
      error: @domain.dkim_error
    )
  end

  def return_path_record
    record(
      "CNAME",
      @domain.return_path_domain,
      Postal::Config.dns.return_path_domain,
      DNS_PURPOSES[:return_path],
      status: @domain.return_path_status,
      error: @domain.return_path_error
    )
  end

  def mx_records
    Postal::Config.dns.mx_records.map do |mx_record|
      record(
        "MX",
        @domain.name,
        mx_record,
        DNS_PURPOSES[:mx],
        priority: MX_PRIORITY,
        status: @domain.mx_status,
        error: @domain.mx_error
      )
    end
  end

  def record(type, host, value, purpose, priority: nil, status: nil, error: nil)
    attributes = {
      type: type,
      host: host,
      value: value,
      required: record_required?(purpose),
      purpose: purpose,
      status: status,
      error: error
    }
    attributes[:priority] = priority if priority
    attributes
  end

  def verification_status
    if @domain.verified?
      { status: "OK", error: nil }
    else
      { status: "Pending", error: nil }
    end
  end

  def record_required?(purpose)
    !OPTIONAL_PURPOSES.include?(purpose)
  end

  def status_for(name)
    {
      status: @domain.public_send("#{name}_status"),
      error: @domain.public_send("#{name}_error")
    }
  end

end
