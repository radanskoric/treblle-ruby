# frozen_string_literal: true

require 'treblle/models/response'
require 'treblle/models/response/exception'
require 'active_support'
require 'json'

module Treblle
  class ResponseBuilder
    def initialize(rack_response)
      @rack_response = rack_response
    end

    def build
      Models::Response.new.tap do |response|
        apply_to_response(response)
      end
    end

    private

    attr_reader :rack_response, :handle_errors

    def apply_to_response(response)
      status, headers, response_data = rack_response || [500, [], nil]

      response.status = status
      response.headers = headers
      response.body = parse_body(response_data) || parse_error_body(response_data)
      response.size = calculate_size(response.body, response.headers)
      response.exception = Models::Response::Exception.new(response) if status >= 400

      response
    end

    def calculate_size(body, headers)
      return 0 if body.nil?

      # Ovaj encode ovdje serializira nesto sta je liniju prije bilo deserijalizirano.
      # U svrhu cim manjeg overhead-a, mozda ima smisla samo koristiti size od originala?
      headers.fetch('content-length', nil) || ActiveSupport::JSON.encode(body).size
    end

    def parse_body(response_data)
      return nil unless response_data.respond_to?(:body)

      JSON.parse(response_data.body)
    rescue JSON::ParserError
      response_data.body
    end

    def parse_error_body(response_data)
      return nil unless response_data.is_a?(Array) && !response_data.empty?

      JSON.parse(response_data.first)
    rescue JSON::ParserError
      response_data.body
    end
  end
end
