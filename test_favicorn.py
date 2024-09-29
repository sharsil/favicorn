import unittest
from unittest.mock import patch, mock_open
from favicorn import Favicon  # Import your Favicon class
import requests
import dns

class TestFavicon(unittest.TestCase):
    
    def setUp(self):
        """Common setup for tests"""
        with open('test-favicon.png', 'rb') as file:
            self.sample_favicon_content = file.read()

        self.expected_murmur_hash = 553299689
        self.expected_md5 = 'e8a7fa0c08b4e1670b633f7246fd57ec'
        self.expected_base64 = 'aWNvbl9oYXNoPSI1NTMyOTk2ODki'
        self.expected_sha256 = '95c171ef60f0cdf6f11543b0ce0a4361ad014de84bae370dc2b2a61cd5482c84'
        self.expected_hex_hash = '20faaee9'
        
    @patch('requests.get')
    def test_from_url(self, mock_get):
        """Test Favicon creation from URL"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.content = self.sample_favicon_content
        mock_get.return_value.headers = {'Content-Type': 'image/x-icon'}

        favicon = Favicon.from_url('http://example.com/favicon.ico')
        
        # Check that the content and hashes were generated correctly
        
        self.assertEqual(favicon.md5_hash, self.expected_md5, "MD5 hash does not match expected value.")
        self.assertEqual(favicon.sha256_hash, self.expected_sha256, "SHA256 hash does not match expected value.")
        self.assertEqual(favicon.murmur_hash, self.expected_murmur_hash, "MurmurHash does not match expected value.")
        self.assertEqual(favicon.hex_hash, self.expected_hex_hash, "Hex hash does not match expected value.")
        self.assertEqual(favicon.base64_hash, self.expected_base64, "Base64 hash does not match expected value.")
        
        # Validate the links_text output (partially, for brevity)
        links_output = favicon.links_text()
        self.assertIn('ZoomEye', links_output)
        self.assertIn('Shodan', links_output)

    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists', return_value=True)
    def test_from_file(self, mock_exists, mock_file):
        """Test Favicon creation from file"""
        # Set the read_data dynamically using self.sample_favicon_content
        mock_file.return_value.read.return_value = self.sample_favicon_content

        # Create Favicon object from file
        favicon = Favicon.from_file('/path/to/fake/favicon.ico')
        
        # Check that the content and hashes were generated correctly
        self.assertEqual(favicon.md5_hash, self.expected_md5)
        self.assertEqual(favicon.sha256_hash, self.expected_sha256)
        self.assertEqual(favicon.hex_hash, self.expected_hex_hash)
        
        # Validate the links_text output
        links_output = favicon.links_text()
        self.assertIn('ZoomEye', links_output)
        self.assertIn('Fofa', links_output)

    def test_links_text_output(self):
        """Test if links_text generates proper links"""
        favicon = Favicon(self.sample_favicon_content, source="http://example.com", type="direct link")
        
        links_output = favicon.links_text()
        platforms = favicon.get_platform_names()

        for platform in platforms:
            self.assertIn(platform, links_output)
    
    # @patch('dns.resolver.Resolver.resolve')
    # @patch('requests.get')
    # def test_resolve_domain(self, mock_get, mock_resolve):
    #     """Test resolving a domain and fetching favicon from the IP"""
    #     mock_resolve.return_value = [dns.rdtypes.ANY.A.A(None, None, '93.184.216.34')]
    #     mock_get.return_value.status_code = 200
    #     mock_get.return_value.content = self.sample_favicon_content

    #     favicon = Favicon.from_url('http://93.184.216.34/favicon.ico')

    #     # Check hashes for resolved IP
    #     self.assertEqual(favicon.md5_hash, self.expected_md5)
    #     self.assertEqual(favicon.sha256_hash, self.expected_sha256)
    #     self.assertEqual(favicon.hex_hash, self.expected_hex_hash)

if __name__ == '__main__':
    unittest.main()