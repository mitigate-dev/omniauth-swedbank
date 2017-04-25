require 'omniauth'
require 'base64'

module OmniAuth
  module Strategies
    class Swedbank
      include OmniAuth::Strategy

      AUTH_SERVICE = '4002'
      AUTH_VERSION = '008'

      args [:private_key, :public_key, :snd_id, :rec_id]

      option :private_key, nil
      option :public_key, nil
      option :snd_id, nil
      option :rec_id, nil

      option :name, 'swedbank'
      option :site, 'https://ib.swedbank.lv/banklink'

      def stamp
        return @stamp if @stamp
        @stamp = Time.now.strftime('%Y%m%d%H%M%S') + SecureRandom.random_number(999999).to_s.rjust(6, '0')
      end

      def prepend_length(value)
        # prepend length to string in 0xx format
        [ value.to_s.length.to_s.rjust(3, '0'), value.dup.to_s.force_encoding('ascii')].join
      end

      def signature_input
        [
          AUTH_SERVICE,             # VK_SERVICE
          AUTH_VERSION,             # VK_VERSION
          options.snd_id,           # VK_SND_ID
          options.rec_id,           # VK_REC_ID
          stamp,                    # VK_NONCE
          callback_url              # VK_RETURN
        ].map{|v| prepend_length(v)}.join
      end

      def signature(priv_key)
        Base64.encode64(priv_key.sign(OpenSSL::Digest::SHA1.new, signature_input))
      end

      uid do
        request.params['VK_INFO'].match(/ISIK:(\d{6}\-\d{5})/)[1]
      end

      info do
        {
          full_name: request.params['VK_INFO'].match(/NIMI:(.+)/)[1]
        }
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

        if request.params['VK_SERVICE'] != '3003'
          return fail!(:unsupported_response_service_err)
        end

        if request.params['VK_VERSION'] != '008'
          return fail!(:unsupported_response_version_err)
        end

        if request.params['VK_ENCODING'] != 'UTF-8'
          return fail!(:unsupported_response_encoding_err)
        end

        sig_str = [
          request.params['VK_SERVICE'],
          request.params['VK_VERSION'],
          request.params['VK_SND_ID'],
          request.params['VK_REC_ID'],
          request.params['VK_NONCE'],
          request.params['VK_INFO']
        ].map{|v| prepend_length(v)}.join

        raw_signature = Base64.decode64(request.params['VK_MAC'])

        if !pub_key.verify(OpenSSL::Digest::SHA1.new, raw_signature, sig_str)
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

        form = OmniAuth::Form.new(:title => I18n.t('omniauth.swedbank.please_wait'), :url => options.site)

        {
          'VK_SERVICE' => AUTH_SERVICE,
          'VK_VERSION' => AUTH_VERSION,
          'VK_SND_ID' => options.snd_id,
          'VK_REC_ID' => options.rec_id,
          'VK_NONCE' => stamp,
          'VK_RETURN' => callback_url,
          'VK_MAC' => signature(priv_key),
          'VK_LANG' => 'LAT',
          'VK_ENCODING' => 'UTF-8'
        }.each do |name, val|
          form.html "<input type=\"hidden\" name=\"#{name}\" value=\"#{val}\" />"
        end

        form.button I18n.t('omniauth.swedbank.click_here_if_not_redirected')

        form.instance_variable_set('@html',
          form.to_html.gsub('</form>', '</form><script type="text/javascript">document.forms[0].submit();</script>'))
        form.to_response
      end
    end
  end
end
