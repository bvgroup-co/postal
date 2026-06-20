# frozen_string_literal: true

ActiveRecord::ConnectionAdapters::AbstractAdapter.set_callback :checkout, :after, :verify!
