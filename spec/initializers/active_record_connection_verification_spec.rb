# frozen_string_literal: true

require "rails_helper"

RSpec.describe "active record connection verification" do
  it "registers verify on checkout" do
    callback_filters = ActiveRecord::ConnectionAdapters::AbstractAdapter.__callbacks[:checkout].map do |callback|
      [callback.kind, callback.filter]
    end

    expect(callback_filters).to include([:after, :verify!])
  end

  it "verifies pooled connections before checkout returns them to application code" do
    verify_calls = 0

    allow_any_instance_of(ActiveRecord::ConnectionAdapters::Mysql2Adapter).to receive(:verify!).and_wrap_original do |verify, *args|
      verify_calls += 1
      verify.call(*args)
    end

    ActiveRecord::Base.connection_pool.release_connection
    connection = ActiveRecord::Base.connection_pool.checkout

    expect(verify_calls).to eq(1)
    expect(connection.instance_variable_get(:@verified)).to be(true)
  ensure
    ActiveRecord::Base.connection_pool.checkin(connection) if connection
  end
end
