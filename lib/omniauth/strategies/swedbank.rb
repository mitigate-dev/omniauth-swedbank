require 'omniauth'
require 'base64'

module OmniAuth
  module Strategies
    class Swedbank
      include OmniAuth::Strategy

      V008_AUTH_SERVICE = '4002'
      V008_RESPONSE_SERVICE = '3003'
      V009_AUTH_SERVICE = '4012'
      V009_RESPONSE_SERVICE = '3013'

      def self.render_nonce?
         defined?(ActionDispatch::ContentSecurityPolicy::Request) != nil
      end
      if render_nonce?
        include ActionDispatch::ContentSecurityPolicy::Request
        delegate :get_header, :set_header, to: :request
      end

      args [:private_key, :public_key, :snd_id, :rec_id]

      option :private_key, nil
      option :public_key, nil
      option :snd_id, nil
      option :rec_id, nil

      option :name, 'swedbank'
      option :site, 'https://www.swedbank.lv/banklink'
      option :version, '008'

      def version_009?
        options.version == '009'
      end

      def auth_service
        version_009? ? V009_AUTH_SERVICE : V008_AUTH_SERVICE
      end

      def response_service
        version_009? ? V009_RESPONSE_SERVICE : V008_RESPONSE_SERVICE
      end

      def digest
        version_009? ? OpenSSL::Digest::SHA512.new : OpenSSL::Digest::SHA1.new
      end

      def stamp
        return @stamp if @stamp
        @stamp = Time.now.strftime('%Y%m%d%H%M%S') + SecureRandom.random_number(999999).to_s.rjust(6, '0')
      end

      def datetime
        @datetime ||= Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')
      end

      def rid
        ''
      end

      def prepend_length(value)
        # prepend length to string in 0xx format
        [ value.to_s.length.to_s.rjust(3, '0'), value.dup.to_s.force_encoding('ascii')].join
      end

      def signature_input
        fields = if version_009?
          [
            auth_service,       # VK_SERVICE
            options.version,    # VK_VERSION
            options.snd_id,     # VK_SND_ID
            options.rec_id,     # VK_REC_ID
            stamp,              # VK_NONCE
            callback_url,       # VK_RETURN
            datetime,           # VK_DATETIME
            rid                 # VK_RID
          ]
        else
          [
            auth_service,       # VK_SERVICE
            options.version,    # VK_VERSION
            options.snd_id,     # VK_SND_ID
            options.rec_id,     # VK_REC_ID
            stamp,              # VK_NONCE
            callback_url        # VK_RETURN
          ]
        end
        fields.map{|v| prepend_length(v)}.join
      end

      def signature(priv_key)
        Base64.encode64(priv_key.sign(digest, signature_input))
      end

      uid do
        if version_009?
          request.params['VK_USER_ID']
        else
          request.params['VK_INFO'].match(/ISIK:(\d{6}\-\d{5})/)[1]
        end
      end

      info do
        if version_009?
          {
            full_name: request.params['VK_USER_NAME'],
            country: request.params['VK_COUNTRY']
          }
        else
          {
            full_name: request.params['VK_INFO'].match(/NIMI:(.+)/)[1]
          }
        end
      end

      extra do
        { raw_info: request.params }
      end

      def callback_phase
        begin
          pub_key = OpenSSL::X509::Certificate.new(options.public_key).public_key
        rescue => e
          return fail!(:public_key_load_err, e)
        end

        if request.params['VK_SERVICE'] != response_service
          return fail!(:unsupported_response_service_err)
        end

        if request.params['VK_VERSION'] != options.version
          return fail!(:unsupported_response_version_err)
        end

        if request.params['VK_ENCODING'] != 'UTF-8'
          return fail!(:unsupported_response_encoding_err)
        end

        sig_str = if version_009?
          [
            request.params['VK_SERVICE'],
            request.params['VK_VERSION'],
            request.params['VK_DATETIME'],
            request.params['VK_SND_ID'],
            request.params['VK_REC_ID'],
            request.params['VK_NONCE'],
            request.params['VK_USER_NAME'],
            request.params['VK_USER_ID'],
            request.params['VK_COUNTRY'],
            request.params['VK_OTHER'],
            request.params['VK_TOKEN'],
            request.params['VK_RID']
          ].map{|v| prepend_length(v)}.join
        else
          [
            request.params['VK_SERVICE'],
            request.params['VK_VERSION'],
            request.params['VK_SND_ID'],
            request.params['VK_REC_ID'],
            request.params['VK_NONCE'],
            request.params['VK_INFO']
          ].map{|v| prepend_length(v)}.join
        end

        raw_signature = Base64.decode64(request.params['VK_MAC'])

        if !pub_key.verify(digest, raw_signature, sig_str)
          return fail!(:invalid_response_signature_err)
        end

        super
      end

      def request_phase
        begin
          priv_key = OpenSSL::PKey::RSA.new(options.private_key)
        rescue => e
          return fail!(:private_key_load_err, e)
        end

        unless version_009?
          warn "[DEPRECATION] omniauth-swedbank: Swedbank banklink v008 will be shut down on 2026-06-02. " \
               "Please migrate to v009 by setting `version: '009'` in your provider config. " \
               "See https://www.swedbank.lv/static/business/banklink/LV_Authentication_008_vs_009_instruction.pdf"
        end

        set_locale_from_query_param

        form = OmniAuth::Form.new(:title => I18n.t('omniauth.swedbank.please_wait'), :url => options.site)

        params = {
          'VK_SERVICE' => auth_service,
          'VK_VERSION' => options.version,
          'VK_SND_ID' => options.snd_id,
          'VK_REC_ID' => options.rec_id,
          'VK_NONCE' => stamp,
          'VK_RETURN' => callback_url,
          'VK_MAC' => signature(priv_key),
          'VK_LANG' => resolve_bank_ui_language,
          'VK_ENCODING' => 'UTF-8'
        }

        if version_009?
          params['VK_DATETIME'] = datetime
          params['VK_RID'] = rid
        end

        params.each do |name, val|
          form.html "<input type=\"hidden\" name=\"#{name}\" value=\"#{escape(val)}\" />"
        end

        form.button I18n.t('omniauth.swedbank.click_here_if_not_redirected')

        nonce_attribute = nil
        if self.class.render_nonce?
          nonce_attribute = " nonce='#{escape(content_security_policy_nonce)}'"
        end
        form.instance_variable_set('@html',
          form.to_html.gsub('</form>', "</form><script type=\"text/javascript\"#{nonce_attribute}>document.forms[0].submit();</script>"))
        form.to_response
      end

      private

      def set_locale_from_query_param
        locale = request.params['locale']
        if (locale != nil && locale.strip != '' && I18n.locale_available?(locale))
          I18n.locale = locale
        end
      end

      def resolve_bank_ui_language
        case I18n.locale
        when :ru then 'RUS'
        when :en then 'ENG'
        when :et then 'EST'
        when :lt then 'LIT'
        else 'LAT'
        end
      end

      def escape(html_attribute_value)
         CGI.escapeHTML(html_attribute_value) unless html_attribute_value.nil?
      end
    end
  end
end
