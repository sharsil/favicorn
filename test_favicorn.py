import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, mock_open, patch

import favicorn
from favicorn import (
    Favicon,
    NetlasPreviewAPIKeyFetcher,
    ShodanPreviewAPIKeyFetcher,
    ZoomEyePreviewFetcher,
    make_se_links,
    resolve_domain,
)


def _read_test_favicon():
    with open('test-favicon.png', 'rb') as f:
        return f.read()


class TestFavicon(unittest.TestCase):

    def setUp(self):
        self.sample_favicon_content = _read_test_favicon()

        # Favicon.__init__ otherwise hits app.netlas.io on every test.
        p = patch.object(Favicon, 'get_perceptual_hash', return_value='deadbeef')
        p.start()
        self.addCleanup(p.stop)

        self.expected_murmur_hash = 553299689
        self.expected_md5 = 'e8a7fa0c08b4e1670b633f7246fd57ec'
        self.expected_base64 = 'aWNvbl9oYXNoPSI1NTMyOTk2ODki'
        self.expected_sha256 = '95c171ef60f0cdf6f11543b0ce0a4361ad014de84bae370dc2b2a61cd5482c84'
        self.expected_hex_hash = '20faaee9'

    @patch('requests.get')
    def test_from_url(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.content = self.sample_favicon_content
        mock_get.return_value.headers = {'Content-Type': 'image/x-icon'}

        favicon = Favicon.from_url('http://example.com/favicon.ico')

        self.assertEqual(favicon.md5_hash, self.expected_md5)
        self.assertEqual(favicon.sha256_hash, self.expected_sha256)
        self.assertEqual(favicon.murmur_hash, self.expected_murmur_hash)
        self.assertEqual(favicon.hex_hash, self.expected_hex_hash)
        self.assertEqual(favicon.base64_hash, self.expected_base64)

        links_output = favicon.links_text()
        self.assertIn('ZoomEye', links_output)
        self.assertIn('Shodan', links_output)

    @patch('requests.get')
    def test_from_url_rejects_non_image_content_type(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.content = b'<html>not an icon</html>'
        mock_get.return_value.headers = {'Content-Type': 'text/html'}

        with self.assertRaises(Exception):
            Favicon.from_url('http://example.com/page')

    @patch('requests.get')
    def test_from_url_raises_on_non_200(self, mock_get):
        mock_get.return_value.status_code = 404
        with self.assertRaises(Exception):
            Favicon.from_url('http://example.com/missing.ico')

    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists', return_value=True)
    def test_from_file(self, mock_exists, mock_file):
        mock_file.return_value.read.return_value = self.sample_favicon_content

        favicon = Favicon.from_file('/path/to/fake/favicon.ico')

        self.assertEqual(favicon.md5_hash, self.expected_md5)
        self.assertEqual(favicon.sha256_hash, self.expected_sha256)
        self.assertEqual(favicon.hex_hash, self.expected_hex_hash)
        links_output = favicon.links_text()
        self.assertIn('ZoomEye', links_output)
        self.assertIn('Fofa', links_output)

    def test_from_file_missing(self):
        with self.assertRaises(FileNotFoundError):
            Favicon.from_file('/nonexistent/path/missing.ico')

    def test_from_file_rejects_non_image_extension(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as tmp:
            tmp.write(b'not an image')
            path = tmp.name
        try:
            with self.assertRaises(ValueError):
                Favicon.from_file(path)
        finally:
            os.unlink(path)

    def test_eq_and_hash(self):
        f1 = Favicon(self.sample_favicon_content, source='a', type='t')
        f2 = Favicon(self.sample_favicon_content, source='b', type='t')
        self.assertEqual(f1, f2)
        self.assertEqual(hash(f1), hash(f2))
        self.assertFalse(f1 == 'not a favicon')

    def test_generate_links_dict_values(self):
        favicon = Favicon(self.sample_favicon_content, source='http://example.com', type='direct link')
        links = favicon.generate_links_dict()

        expected_platforms = {
            'ZoomEye', 'Shodan', 'Fofa', 'VirusTotal', 'BinaryEdge',
            'Netlas', 'Netlas Perceptual', 'Censys', 'ODIN', 'CriminalIP', 'HunterHow',
        }
        self.assertEqual(set(links.keys()), expected_platforms)

        murmur = str(self.expected_murmur_hash)
        self.assertIn(murmur, links['ZoomEye'])
        self.assertIn(murmur, links['Shodan'])
        self.assertIn(self.expected_base64, links['Fofa'])
        self.assertIn(self.expected_md5, links['VirusTotal'])
        self.assertIn(self.expected_md5, links['BinaryEdge'])
        self.assertIn(self.expected_sha256, links['Netlas'])
        self.assertIn('deadbeef', links['Netlas Perceptual'])  # patched average_hash
        self.assertIn(self.expected_md5, links['Censys'])
        self.assertIn(murmur, links['ODIN'])
        self.assertIn(self.expected_hex_hash, links['CriminalIP'])
        self.assertIn(self.expected_md5, links['HunterHow'])

    def test_links_text_lists_all_platforms(self):
        favicon = Favicon(self.sample_favicon_content, source='http://example.com', type='direct link')
        text = favicon.links_text()
        for platform in favicon.get_platform_names():
            self.assertIn(platform, text)


class TestShodanFetcherParse(unittest.TestCase):

    def test_parse_extracts_domains_ips_and_waf(self):
        data = {
            'total': 2,
            'matches': [
                {
                    'hostnames': ['example.com'], 'port': 443, 'ip_str': '1.2.3.4',
                    'http': {'waf': 'Cloudflare'},
                },
                {
                    'hostnames': ['other.com'], 'port': 80, 'ip_str': '5.6.7.8',
                    'http': {},
                },
            ],
        }
        total, domains, ip_by_waf = ShodanPreviewAPIKeyFetcher._parse_response(data)

        self.assertEqual(total, 2)
        self.assertIn('example.com:443', domains)
        self.assertIn('other.com:80', domains)
        self.assertEqual(ip_by_waf['Cloudflare'], ['1.2.3.4'])
        self.assertEqual(ip_by_waf['No CDN/WAF'], ['5.6.7.8'])

    def test_parse_empty(self):
        total, domains, ip_by_waf = ShodanPreviewAPIKeyFetcher._parse_response({'total': 0, 'matches': []})
        self.assertEqual(total, 0)
        self.assertEqual(domains, [])
        self.assertEqual(ip_by_waf, {})


class TestZoomEyeFetcherParse(unittest.TestCase):

    def test_parse_with_waf(self):
        data = {
            'total': 1,
            'matches': [
                {
                    'site': 'example.com',
                    'portinfo': {'port': 443},
                    'ip': ['1.2.3.4'],
                    'waf': [{'name': {'en': 'CloudFlare'}}],
                },
            ],
        }
        total, domains, ip_by_waf = ZoomEyePreviewFetcher._parse_response(data)
        self.assertEqual(total, 1)
        self.assertEqual(domains, ['example.com:443'])
        self.assertEqual(ip_by_waf['CloudFlare'], ['1.2.3.4'])

    def test_parse_without_waf_uses_default(self):
        data = {
            'total': 1,
            'matches': [
                {'site': 'a.com', 'portinfo': {'port': 80}, 'ip': '9.9.9.9', 'waf': []},
            ],
        }
        total, domains, ip_by_waf = ZoomEyePreviewFetcher._parse_response(data)
        self.assertEqual(domains, ['a.com:80'])
        self.assertEqual(ip_by_waf['No WAF'], ['9.9.9.9'])

    def test_parse_real_fixture(self):
        path = os.path.join('api_responses', '553299689_zoomeye.json')
        if not os.path.exists(path):
            self.skipTest(f'fixture {path} missing')
        with open(path) as f:
            data = json.load(f)
        total, domains, ip_by_waf = ZoomEyePreviewFetcher._parse_response(data)
        self.assertGreater(total, 0)
        self.assertGreater(len(domains), 0)
        self.assertTrue(any('emojipedia.org' in d for d in domains))
        self.assertIn('CloudFlare', ip_by_waf)


class TestNetlasFetcherParse(unittest.TestCase):

    def test_parse_extracts_domains_and_dedups_ips(self):
        data = {
            'items': [
                {'data': {'host': 'example.com', 'port': 443, 'ip': '1.2.3.4'}},
                {'data': {'host': 'example.com', 'port': 443, 'ip': '1.2.3.4'}},
                {'data': {'host': 'other.com', 'port': 80, 'ip': '5.6.7.8'}},
            ],
        }
        total, domains, ip_by_waf = NetlasPreviewAPIKeyFetcher._parse_response(data)
        self.assertEqual(total, 3)
        self.assertEqual(set(domains), {'example.com:443', 'other.com:80'})
        self.assertEqual(set(ip_by_waf['No WAF']), {'1.2.3.4', '5.6.7.8'})

    def test_parse_empty(self):
        total, domains, ip_by_waf = NetlasPreviewAPIKeyFetcher._parse_response({'items': []})
        self.assertEqual(total, 0)
        self.assertEqual(domains, [])
        self.assertEqual(ip_by_waf, {'No WAF': []})


class TestFetcherCache(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmpdir, ignore_errors=True))
        p = patch.object(favicorn, 'OUTPUT_DIR', self.tmpdir)
        p.start()
        self.addCleanup(p.stop)

    def test_save_and_load_roundtrip(self):
        data = {'matches': [{'hostnames': ['example.com'], 'port': 443}], 'total': 1}
        ShodanPreviewAPIKeyFetcher._save_response_to_file(data, 12345)

        path = os.path.join(self.tmpdir, '12345_Shodan.json')
        self.assertTrue(os.path.exists(path))

        loaded = ShodanPreviewAPIKeyFetcher._load_response_from_file(12345)
        self.assertEqual(loaded, data)

    def test_load_missing_returns_none(self):
        self.assertIsNone(ShodanPreviewAPIKeyFetcher._load_response_from_file(99999))

    def test_save_creates_output_dir(self):
        nested = os.path.join(self.tmpdir, 'sub', 'dir')
        with patch.object(favicorn, 'OUTPUT_DIR', nested):
            ZoomEyePreviewFetcher._save_response_to_file({'total': 0}, 1)
            self.assertTrue(os.path.exists(os.path.join(nested, '1_ZoomEye.json')))

    def test_filename_uses_platform_name(self):
        ShodanPreviewAPIKeyFetcher._save_response_to_file({'total': 0}, 7)
        ZoomEyePreviewFetcher._save_response_to_file({'total': 0}, 7)
        NetlasPreviewAPIKeyFetcher._save_response_to_file({'items': []}, 7)
        names = set(os.listdir(self.tmpdir))
        self.assertEqual(names, {'7_Shodan.json', '7_ZoomEye.json', '7_Netlas.json'})


class TestSearchEngineLinks(unittest.TestCase):

    def test_make_se_links_returns_expected_urls(self):
        links = make_se_links('example.com')
        self.assertEqual([name for name, _ in links], ['Google 16x16', 'Google 32x32', 'DuckDuckGo', 'Icon Horse'])
        url_for = dict(links)
        self.assertEqual(url_for['Google 16x16'], 'https://www.google.com/s2/favicons?domain=example.com&size=16')
        self.assertEqual(url_for['Google 32x32'], 'https://www.google.com/s2/favicons?domain=example.com&size=32')
        self.assertEqual(url_for['DuckDuckGo'], 'https://icons.duckduckgo.com/ip3/example.com.ico')
        self.assertEqual(url_for['Icon Horse'], 'https://icon.horse/icon/example.com')


class TestResolveDomain(unittest.TestCase):

    @patch('favicorn.dns.resolver.Resolver')
    def test_returns_ip_list(self, MockResolver):
        a, b = MagicMock(), MagicMock()
        a.to_text.return_value = '93.184.216.34'
        b.to_text.return_value = '93.184.216.35'
        MockResolver.return_value.resolve.return_value = [a, b]

        self.assertEqual(resolve_domain('example.com'), ['93.184.216.34', '93.184.216.35'])

    @patch('favicorn.dns.resolver.Resolver')
    def test_returns_empty_on_error(self, MockResolver):
        MockResolver.return_value.resolve.side_effect = Exception('NXDOMAIN')
        self.assertEqual(resolve_domain('definitely-bogus.invalid'), [])


if __name__ == '__main__':
    unittest.main()
