# frozen_string_literal: true

require "rails_helper"

RSpec.describe "Legacy Domains API", type: :request do
  let(:server) { create(:server) }
  let(:credential) { create(:credential, server: server) }
  let(:headers) { { "x-server-api-key" => credential.key, "content-type" => "application/json" } }

  def parsed_body
    JSON.parse(response.body)
  end

  def record_for(purpose)
    parsed_body["records"].find { |record| record["purpose"] == purpose }
  end

  describe "POST /api/v1/domains" do
    it "creates an unverified DNS domain for the authenticated server" do
      post "/api/v1/domains", headers: headers, params: { name: "Example.COM" }.to_json

      expect(response.status).to eq 201
      domain = server.domains.find_by!(name: "example.com")
      expect(domain).to have_attributes(verification_method: "DNS", verified_at: nil)
      expect(parsed_body).to include(
        "id" => domain.uuid,
        "uuid" => domain.uuid,
        "name" => "example.com",
        "verified" => false
      )
    end

    it "returns DNS records needed by Plunk" do
      post "/api/v1/domains", headers: headers, params: { name: "example.com" }.to_json

      expect(parsed_body["records"]).to include(
        hash_including("type" => "TXT", "host" => "example.com", "purpose" => "ownership-verification", "required" => true),
        hash_including("type" => "TXT", "host" => "example.com", "purpose" => "spf", "required" => true),
        hash_including("type" => "TXT", "purpose" => "dkim", "required" => true),
        hash_including("type" => "CNAME", "purpose" => "return-path", "required" => false)
      )
      expect(parsed_body["records"]).to include(hash_including("type" => "MX", "priority" => 10, "purpose" => "inbound-mx"))
      parsed_body["records"].each do |record|
        expect(record.keys).to include("type", "host", "value", "purpose", "required", "status", "error")
      end
      expect(parsed_body["statuses"]["verification"]).to include("status" => "Pending", "error" => nil)
    end

    it "returns duplicate domains for the same server idempotently" do
      create(:domain, owner: server, name: "example.com")

      expect do
        post "/api/v1/domains", headers: headers, params: { name: "example.com" }.to_json
      end.to_not(change { server.domains.count })
      expect(response.status).to eq 200
      expect(parsed_body["uuid"]).to be_present
    end

    it "rejects invalid domains" do
      post "/api/v1/domains", headers: headers, params: { name: "bad domain" }.to_json

      expect(response.status).to eq 422
    end

    it "rejects missing authentication" do
      post "/api/v1/domains", params: { name: "example.com" }.to_json

      expect(response.status).to eq 200
      expect(parsed_body["data"]["code"]).to eq "AccessDenied"
    end

    it "rejects invalid authentication" do
      post "/api/v1/domains", headers: { "x-server-api-key" => "invalid" }, params: { name: "example.com" }.to_json

      expect(response.status).to eq 200
      expect(parsed_body["data"]["code"]).to eq "InvalidServerAPIKey"
    end

    it "rejects suspended servers" do
      suspended_server = create(:server, :suspended)
      suspended_credential = create(:credential, server: suspended_server)

      post "/api/v1/domains", headers: { "x-server-api-key" => suspended_credential.key }, params: { name: "example.com" }.to_json

      expect(response.status).to eq 200
      expect(parsed_body["data"]["code"]).to eq "ServerSuspended"
    end
  end

  describe "POST /api/v1/domains/:id/check" do
    it "verifies ownership when DNS TXT is present" do
      domain = create(:domain, :unverified, owner: server)
      resolver = double(
        txt: [domain.dns_verification_string],
        mx: [],
        cname: []
      )
      allow_any_instance_of(Domain).to receive(:resolver).and_return(resolver)

      post "/api/v1/domains/#{domain.uuid}/check", headers: headers

      expect(response.status).to eq 200
      expect(domain.reload).to be_verified
      expect(parsed_body["verified"]).to be true
      expect(record_for("ownership-verification")["status"]).to eq "OK"
    end

    it "refreshes DNS setup statuses for verified domains" do
      domain = create(:domain, owner: server)
      allow_any_instance_of(Domain).to receive(:resolver).and_return(
        double(
          txt: [domain.spf_record],
          mx: [[10, Postal::Config.dns.mx_records.first]],
          cname: [Postal::Config.dns.return_path_domain]
        )
      )

      post "/api/v1/domains/#{domain.uuid}/check", headers: headers

      expect(response.status).to eq 200
      expect(domain.reload.spf_status).to eq "OK"
      expect(parsed_body["statuses"]["spf"]).to include("status" => "OK", "error" => nil)
    end

    it "returns 404 for unknown domains" do
      post "/api/v1/domains/unknown/check", headers: headers

      expect(response.status).to eq 404
    end

    it "does not coerce malformed numeric IDs" do
      domain = create(:domain, owner: server)

      post "/api/v1/domains/#{domain.id}-not-a-uuid/check", headers: headers

      expect(response.status).to eq 404
    end

    it "returns 404 for another server's domain" do
      other_domain = create(:domain, owner: create(:server))

      post "/api/v1/domains/#{other_domain.uuid}/check", headers: headers

      expect(response.status).to eq 404
    end
  end

  describe "DELETE /api/v1/domains/:id" do
    it "deletes the authenticated server's domain" do
      domain = create(:domain, owner: server)

      expect do
        delete "/api/v1/domains/#{domain.uuid}", headers: headers
      end.to change { server.domains.count }.by(-1)
      expect(response.status).to eq 204
    end

    it "returns 404 for another server's domain" do
      other_domain = create(:domain, owner: create(:server))

      delete "/api/v1/domains/#{other_domain.uuid}", headers: headers

      expect(response.status).to eq 404
      expect(Domain.exists?(other_domain.id)).to be true
    end

    it "rejects invalid authentication" do
      domain = create(:domain, owner: server)

      delete "/api/v1/domains/#{domain.uuid}", headers: { "x-server-api-key" => "invalid" }

      expect(response.status).to eq 200
      expect(parsed_body["data"]["code"]).to eq "InvalidServerAPIKey"
    end
  end
end
