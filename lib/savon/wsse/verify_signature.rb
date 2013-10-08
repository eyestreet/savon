require 'rexml/document'
require 'savon/wsse/canonicalizer'

module Savon
  class WSSE
    class InvalidSignature < RuntimeError; end
    
    class VerifySignature
      
      class InvalidDigest < RuntimeError; end
      class InvalidSignedValue < RuntimeError; end
      
      attr_reader :response_body, :document
      
      def initialize(response_body)
        @response_body = response_body
        @document = create_document
      end

      def generate_digest(element, algorithm=nil)
        element = element_for_xpath(element) if element.is_a? String
        xml = canonicalize(element)
        digest(xml, algorithm).strip
      end
      
      def supplied_digest(element)
        element = element_for_xpath(element) if element.is_a? String
        find_digest_value element.attributes["Id"]
      end
      
      def digest_algorithm(element)
        element = element_for_xpath(element) if element.is_a? String
        element.attributes["Algorithm"]
      end
      
      def signature_value
        element = element_for_xpath("//wsse:Security/Signature/SignatureValue")
        element ? element.text : ""
      end
      
      def certificate
        certificate_value = element_for_xpath("//wsse:Security/wsse:BinarySecurityToken").text.strip
        OpenSSL::X509::Certificate.new Base64.decode64(certificate_value)
      end
      
      def valid?
        verify
      rescue InvalidDigest, InvalidSignedValue
        return false
      end
      
      def verify!
        verify
      rescue InvalidDigest, InvalidSignedValue => e
        raise InvalidSignature, e.message
      end
      
    private

      def verify
        REXML::XPath.each(document, "//wsse:Security/Signature/SignedInfo/Reference") do |ref|
          digest_algorithm = digest_algorithm( ref.elements["DigestMethod"])
          element_id = ref.attributes["URI"][1..-1] # strip leading '#'
          element = element_for_xpath(%(//*[@wsu:Id="#{element_id}"]))
          raise InvalidDigest, "Invalid Digest for #{element_id}" unless supplied_digest(element) == generate_digest(element, digest_algorithm)
        end

        data = canonicalize(signed_info)
        signature = Base64.decode64(signature_value)

        certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature, data) or raise InvalidSignedValue, "Could not verify the signature value"
      end
      
      def create_document
        REXML::Document.new response_body
      end
      
      def element_for_xpath(xpath)
        REXML::XPath.first(document, xpath)
      end

      def canonicalize(element)
        Canonicalizer.canonicalize(response_body, element)
      end
      
      def signed_info
        REXML::XPath.first(document, "//wsse:Security/Signature/SignedInfo")
      end

      def find_digest_value(id)
        REXML::XPath.first(document, %(//wsse:Security/Signature/SignedInfo/Reference[@URI="##{id}"]/DigestValue)).text
      end
      
      def find_digest_algorithm(id)
        REXML::XPath.first(document, %(//wsse:Security/Signature/SignedInfo/Reference[@URI="##{id}"]/Method)).text
      end
      
      def digest(string, algorithm)
        case algorithm
        when SHA1DigestAlgorithm
          Base64.encode64(Digest::SHA1.digest( string )).strip
        when SHA256DigestAlgorithm
          Base64.encode64(Digest::SHA2.digest( string )).strip
        else
          Base64.encode64(Digest::SHA1.digest( string )).strip
        end
      end
    end
  end
end