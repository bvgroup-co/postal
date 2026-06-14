# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Domain Management API", type: :request do
  let(:server) { create(:server) }
  let(:credential) { create(:credential, server: server) }
  let(:headers) do
    {
      "x-server-api-key" => credential.key,
      "content-type" => "application/json"
    }
  end

  def parsed_body
    JSON.parse(response.body)
  end

  def records_by_purpose
    parsed_body["records"].index_by { |record| record["purpose"] }
  end

  describe "POST /api/v1/domains" do
    context "when no authentication is provided" do
      it "returns an auth error" do
        post "/api/v1/domains", params: { name: "example.com" }.to_json, headers: { "content-type" => "application/json" }
        expect(response.status).to eq 401
        expect(parsed_body["status"]).to eq "error"
        expect(parsed_body["error"]["code"]).to eq "AccessDenied"
      end
    end

    context "when the credential does not match anything" do
      it "returns an auth error" do
        post "/api/v1/domains", params: { name: "example.com" }.to_json, headers: { "x-server-api-key" => "invalid", "content-type" => "application/json" }
        expect(response.status).to eq 401
        expect(parsed_body["status"]).to eq "error"
        expect(parsed_body["error"]["code"]).to eq "InvalidServerAPIKey"
      end
    end

    context "when the credential belongs to a suspended server" do
      it "returns an auth error" do
        suspended_server = create(:server, :suspended)
        suspended_credential = create(:credential, server: suspended_server)

        post "/api/v1/domains", params: { name: "example.com" }.to_json, headers: { "x-server-api-key" => suspended_credential.key, "content-type" => "application/json" }
        expect(response.status).to eq 403
        expect(parsed_body["status"]).to eq "error"
        expect(parsed_body["error"]["code"]).to eq "ServerSuspended"
      end
    end

    it "creates an unverified server-scoped DNS domain" do
      expect do
        post "/api/v1/domains", params: { name: "Example.COM." }.to_json, headers: headers
      end.to change { server.domains.count }.by(1)

      domain = server.domains.last
      expect(response.status).to eq 201
      expect(domain.name).to eq "example.com"
      expect(domain.verification_method).to eq "DNS"
      expect(domain.verified_at).to be_nil
      expect(parsed_body).to include(
        "id" => domain.uuid,
        "uuid" => domain.uuid,
        "name" => "example.com",
        "verified" => false,
        "dns_ok" => false,
        "dns_checked_at" => nil
      )
    end

    it "returns the existing server-scoped domain idempotently" do
      domain = create(:domain, :unverified, owner: server, name: "example.com")

      expect do
        post "/api/v1/domains", params: { name: "example.com" }.to_json, headers: headers
      end.to_not(change { server.domains.count })

      expect(response.status).to eq 200
      expect(parsed_body["uuid"]).to eq domain.uuid
    end

    it "does not mutate an existing server-scoped domain" do
      domain = create(:domain, owner: server, name: "example.com", verification_method: "Email")
      original_verification_token = domain.verification_token

      post "/api/v1/domains", params: { name: "example.com" }.to_json, headers: headers

      domain.reload
      expect(response.status).to eq 200
      expect(domain.verification_method).to eq "Email"
      expect(domain.verification_token).to eq original_verification_token
    end

    it "allows the same name on another server without cross-server access" do
      other_server = create(:server)
      create(:domain, owner: other_server, name: "example.com")

      expect do
        post "/api/v1/domains", params: { name: "example.com" }.to_json, headers: headers
      end.to change { server.domains.count }.by(1)

      expect(response.status).to eq 201
      expect(parsed_body["name"]).to eq "example.com"
      expect(server.domains.find_by(name: "example.com")).to be_present
    end

    it "includes ownership, SPF, DKIM, MX, and return-path records" do
      post "/api/v1/domains", params: { name: "example.com" }.to_json, headers: headers

      domain = server.domains.last
      verification_record = records_by_purpose["ownership-verification"]
      spf_record = records_by_purpose["spf"]
      dkim_record = records_by_purpose["dkim"]
      mx_record = parsed_body["records"].find { |record| record["purpose"] == "inbound-mx" && record["value"] == Postal::Config.dns.mx_records.first }
      return_path_record = records_by_purpose["return-path"]

      expect(verification_record).to include("type" => "TXT", "host" => "example.com", "value" => domain.dns_verification_string, "required" => true, "status" => "Pending", "error" => nil)
      expect(spf_record).to include("type" => "TXT", "host" => "example.com", "value" => domain.spf_record, "required" => true, "status" => nil, "error" => nil)
      expect(dkim_record).to include("type" => "TXT", "host" => domain.dkim_record_name, "value" => domain.dkim_record, "required" => true, "status" => nil, "error" => nil)
      expect(mx_record).to include("type" => "MX", "host" => "example.com", "value" => Postal::Config.dns.mx_records.first, "priority" => 10, "required" => false, "status" => nil, "error" => nil)
      expect(return_path_record).to include(
        "type" => "CNAME",
        "host" => domain.return_path_domain,
        "value" => Postal::Config.dns.return_path_domain,
        "required" => false,
        "status" => nil,
        "error" => nil
      )
    end
  end

  describe "GET /api/v1/domains/:id" do
    it "returns a domain by UUID for the authenticated server" do
      domain = create(:domain, :unverified, owner: server, name: "example.com")

      get "/api/v1/domains/#{domain.uuid}", headers: headers
      expect(response.status).to eq 200
      expect(parsed_body["uuid"]).to eq domain.uuid
      expect(parsed_body["name"]).to eq "example.com"
    end

    it "returns a domain by name for the authenticated server" do
      domain = create(:domain, :unverified, owner: server, name: "example.com")

      get "/api/v1/domains/example.com", headers: headers
      expect(response.status).to eq 200
      expect(parsed_body["uuid"]).to eq domain.uuid
    end

    it "does not return domains belonging to another server" do
      other_domain = create(:domain, owner: create(:server), name: "example.com")

      get "/api/v1/domains/#{other_domain.uuid}", headers: headers
      expect(response.status).to eq 404
      expect(parsed_body["error"]["code"]).to eq "DomainNotFound"
    end
  end

  describe "POST /api/v1/domains/:id/check" do
    let(:domain) { create(:domain, :unverified, owner: server, name: "example.com") }
    let(:resolver) { instance_double(DNSResolver) }

    before do
      allow(DNSResolver).to receive(:for_domain).with(domain.name).and_return(resolver)
      allow(resolver).to receive(:txt).with(domain.name).and_return([domain.dns_verification_string, domain.spf_record])
      allow(resolver).to receive(:txt).with("#{domain.dkim_record_name}.#{domain.name}").and_return([domain.dkim_record])
      allow(resolver).to receive(:mx).with(domain.name).and_return(Postal::Config.dns.mx_records.map { |record| [10, record] })
      allow(resolver).to receive(:cname).with(domain.return_path_domain).and_return([Postal::Config.dns.return_path_domain])
    end

    it "refreshes DNS status and returns normalized statuses and records" do
      post "/api/v1/domains/#{domain.uuid}/check", headers: headers

      domain.reload
      expect(response.status).to eq 200
      expect(domain).to be_verified
      expect(domain.dns_checked_at).to be_present
      expect(parsed_body["verified"]).to be true
      expect(parsed_body["dns_ok"]).to be true
      expect(parsed_body["statuses"]).to match(
        "verification" => { "status" => "OK", "error" => nil },
        "spf" => { "status" => "OK", "error" => nil },
        "dkim" => { "status" => "OK", "error" => nil },
        "mx" => { "status" => "OK", "error" => nil },
        "return_path" => { "status" => "OK", "error" => nil }
      )
      expect(records_by_purpose["spf"]).to include("status" => "OK", "error" => nil)
      expect(records_by_purpose["dkim"]).to include("status" => "OK", "error" => nil)
    end
  end

  describe "DELETE /api/v1/domains/:id" do
    it "removes a domain belonging to the authenticated server" do
      domain = create(:domain, owner: server, name: "example.com")

      expect do
        delete "/api/v1/domains/#{domain.uuid}", headers: headers
      end.to change { server.domains.count }.by(-1)

      expect(response.status).to eq 204
      expect(Domain.exists?(domain.id)).to be false
    end

    it "does not remove domains belonging to another server" do
      other_domain = create(:domain, owner: create(:server), name: "example.com")

      expect do
        delete "/api/v1/domains/#{other_domain.uuid}", headers: headers
      end.to_not(change { Domain.count })

      expect(response.status).to eq 404
      expect(Domain.exists?(other_domain.id)).to be true
    end
  end
end
