require 'omniauth'
require 'base64'

class String
  def prepend_length
    # prepend length to string in 0xx format
    len = self.to_s.length
    self.dup.to_s.force_encoding("ascii").prepend(len.to_s.rjust(3, '0'))
  end
end

module OmniAuth
  module Strategies
    class Swedbank
      # TODO add support for overriding the VK_LANG parameter

      include OmniAuth::Strategy

      AUTH_SERVICE_ID =       "4002"
      AUTH_SERVICE_VERSION =  "008" # This value must not be used as a number, so as to not lose the padding
                                    # Padding is important when generating the VK_MAC value

      args [:private_key_file, :public_key_file, :snd_id, :rec_id]

      option :private_key_file, nil
      option :public_key_file, nil
      option :snd_id, nil
      option :rec_id, nil

      option :name, "swedbank"
      option :site, "https://ib.swedbank.lv/banklink"

      def callback_url
        full_host + script_name + callback_path
      end

      def nonce
        return "test nonce"

        return @nonce if @nonce
        @nonce = ((full_host.gsub(/[\:\/]/, "X") + SecureRandom.uuid.gsub("-", "")).rjust 50, " ")[-50, 50]
      end

      def signature_input
        [
          AUTH_SERVICE_ID,              # VK_SERVICE
          AUTH_SERVICE_VERSION,         # VK_SERVICE
          options.snd_id,               # VK_SND_ID
          options.rec_id,               # VK_REC_ID
          nonce,                        # VK_NONCE
          callback_url                  # VK_RETURN
        ].map(&:prepend_length).join
      end

      def signature(priv_key)
        Base64.encode64(priv_key.sign(OpenSSL::Digest::SHA1.new, signature_input))
      end

      uid do
        request.params["VK_INFO"].match(/ISIK:(\d{6}\-\d{5})/)[1]
      end

      info do
        {
          :full_name => request.params["VK_INFO"].match(/NIMI:(.+)/)[1]
        }
      end

      def callback_phase
        begin
          pub_key = OpenSSL::X509::Certificate.new(File.read(options.public_key_file || "")).public_key
        rescue => e
          return fail!(:public_key_load_err, e)
        end

        if request.params["VK_SERVICE"] != "3003"
          return fail!(:unsupported_response_service_err)
        end

        if request.params["VK_VERSION"] != "008"
          return fail!(:unsupported_response_version_err)
        end

        if request.params["VK_ENCODING"] != "UTF-8"
          return fail!(:unsupported_response_encoding_err)
        end

        sig_str = [
          request.params["VK_SERVICE"],
          request.params["VK_VERSION"],
          request.params["VK_SND_ID"],
          request.params["VK_REC_ID"],
          request.params["VK_NONCE"],
          request.params["VK_INFO"]
        ].map(&:prepend_length).join

        raw_signature = Base64.decode64(request.params["VK_MAC"])

        if !pub_key.verify(OpenSSL::Digest::SHA1.new, raw_signature, sig_str)
          return fail!(:invalid_response_signature_err)
        end

        super
      rescue => e
        fail!(:unknown_callback_err, e)
      end

      def request_phase
        begin
          priv_key = OpenSSL::PKey::RSA.new(File.read(options.private_key_file || ""))
        rescue => e
          return fail!(:private_key_load_err, e)
        end

        OmniAuth.config.form_css = nil
        form = OmniAuth::Form.new(:title => I18n.t("omniauth.swedbank.please_wait"), :url => options.site)

        {
          "VK_SERVICE" => AUTH_SERVICE_ID,
          "VK_VERSION" => AUTH_SERVICE_VERSION,
          "VK_SND_ID" => options.snd_id,
          "VK_REC_ID" => options.rec_id,
          "VK_NONCE" => nonce,
          "VK_RETURN" => callback_url,
          "VK_LANG" => "LAT",
          "VK_MAC" => signature(priv_key)
        }.each do |name, val|
          form.html "<input type=\"hidden\" name=\"#{name}\" value=\"#{val}\" />"
        end

        form.button I18n.t("omniauth.swedbank.click_here_if_not_redirected")

        form.instance_variable_set("@html",
          form.to_html.gsub("</form>", "</form><script type=\"text/javascript\">document.forms[0].submit();</script>"))
        form.to_response
      rescue => e
        fail!(:unknown_request_err, e)
      end
    end
  end
end
