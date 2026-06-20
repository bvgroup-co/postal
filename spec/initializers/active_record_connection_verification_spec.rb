# frozen_string_literal: true

require "rails_helper"

RSpec.describe "active record connection verification" do
  it "registers verify on checkout" do
    callback_filters = ActiveRecord::ConnectionAdapters::AbstractAdapter.__callbacks[:checkout].map do |callback|
      [callback.kind, callback.filter]
    end

    expect(callback_filters).to include([:after, :verify!])
  end

  it "reconnects a pooled connection killed while idle before application SQL runs" do
    connection = ActiveRecord::Base.connection
    killed_connection_id = connection.select_value("SELECT CONNECTION_ID()")
    ActiveRecord::Base.connection_pool.release_connection

    kill_database_connection(killed_connection_id)

    next_connection_id = User.connection.select_value("SELECT CONNECTION_ID()")

    expect(next_connection_id).not_to eq(killed_connection_id)
    expect { User.first }.not_to raise_error
  ensure
    ActiveRecord::Base.connection_pool.release_connection
  end

  def kill_database_connection(connection_id)
    killer = Mysql2::Client.new(
      host: Postal::Config.main_db.host,
      username: Postal::Config.main_db.username,
      password: Postal::Config.main_db.password,
      port: Postal::Config.main_db.port,
      database: Postal::Config.main_db.database
    )
    killer.query("KILL #{Integer(connection_id)}")
  ensure
    killer&.close
  end
end
