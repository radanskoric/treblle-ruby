# frozen_string_literal: true

require 'treblle/version'
require 'treblle/utils/hash_sanitizer'

module Treblle
  class GeneratePayload
    SDK_LANG = 'ruby'
    TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def initialize(request:, response:, started_at:, configuration: Treblle.configuration)
      @request = request
      @response = response
      @started_at = started_at
      @configuration = configuration
    end

    def call
      payload.to_json
    end

    private

    attr_reader :request, :response, :started_at, :configuration

    def sanitize(body)
      Utils::HashSanitizer.sanitize(body, configuration.sensitive_attrs)
    end

    def timestamp
      # Ovaj format samo odbaci vremensku zonu, ali ne prebaci vrijeme prije toga u neku fiksnu zonu.
      # Neznam za sta se tocno koristi vrijeme ali ne bi me cudilo da to pocne uzrokovat probleme za slucaj
      # da je ista aplikacija deployana na serverima u vise razlicitih vremenskih zona.
      # Ako do sad nije bio problem to je vjerojatno zato sto vecina ljudi vrti Rail aplikacije u UTC zoni, ali
      # da sprijecis probleme mozda bi bilo pametno napraviti: started_at.utc.strftime(TIME_FORMAT)
      started_at.strftime(TIME_FORMAT)
    end

    def load_time
      # Kolika je ocekivana preciznost na ovome? Trenutno pozivas Time.now usred procesa generiranja payloada sto znaci
      # da mjeris vrijeme izvrsavanja endpointa + jos nesto malo do neke tocke unutar generiranja json-a.
      # Nije to puno ali ovisno kolika se preciznost ocekuje i koliko je brzi endpoint moglo bi biti bitno.
      # Npr. neki healtcheck endpointi su obicno jako brzi, ovo bi moglo unijeti dovoljno buke da postane nekome bitno.
      # Ne bi se inace zamarao ali fix je jako jednostavan: middleware ionako ima pola logike u sebi, kod ce postat i
      # jednostavniji i precizniji ako middleware odmah izmjeri `load_time`.
      Time.now - started_at
    end

    def payload
      {
        api_key: configuration.api_key,
        project_id: configuration.project_id,
        version: Treblle::API_VERSION,
        sdk: SDK_LANG,
        data: {
          server: {
            ip: request.server.remote_addr,
            timezone: request.server.timezone,
            software: request.server.software,
            signature: '',
            protocol: request.server.protocol,
            os: {
              name: request.server.os_name,
              release: '',
              architecture: request.server.os_architecture
            }
          },
          language: {
            name: SDK_LANG,
            version: RUBY_VERSION
          },
          request: {
            timestamp: timestamp,
            ip: request.client.ip,
            url: request.client.url,
            user_agent: request.client.user_agent,
            method: request.method,
            headers: request.headers,
            body: sanitize(request.body)
          },
          response: {
            headers: response.headers,
            code: response.status,
            size: response.size,
            load_time: load_time,
            body: response.body,
            errors: errors
          }
        }
      }
    end

    def errors
      return [] if response.exception.nil?

      [{
        source: 'onError',
        type: response.exception.type,
        message: response.exception.message,
        file: response.exception.file_path,
        line: response.exception.line_number
      }]
    end
  end
end
