import unittest
from unittest.mock import patch, MagicMock

from havik.gcp.storage import parse_key, evaluate_storage_encryption, evaluate_storage_public_access, list_buckets


class TestGCSModule(unittest.TestCase):

    def test_parse_key(self):
        key = "projects/project-1234/locations/europe-west1/keyRings/storage-eu/cryptoKeys/buckets-eu"
        result = parse_key(key)
        self.assertEqual(result, "europe-west1")

    @patch("havik.gcp.storage.get_client")
    def test_evaluate_storage_encryption_cmek(self, mock_get_client):
        mock_bucket = MagicMock()
        mock_bucket.default_kms_key_name = "projects/project/locations/us/keyRings/kr/cryptoKeys/key"
        mock_bucket.location = "US"

        mock_client = MagicMock()
        mock_client.get_bucket.return_value = mock_bucket
        mock_get_client.return_value = mock_client

        result = evaluate_storage_encryption(mock_bucket)
        expected = {
            'BucketLocation': 'us',
            'Algorithm': 'AES-256',
            'Key': 'Customer Managed',
            'KeyLocation': 'us'
        }
        self.assertEqual(result, expected)

    @patch("havik.gcp.storage.get_client")
    def test_evaluate_storage_encryption_gmek(self, mock_get_client):
        mock_bucket = MagicMock()
        mock_bucket.default_kms_key_name = None
        mock_bucket.location = "europe-west1"

        mock_client = MagicMock()
        mock_client.get_bucket.return_value = mock_bucket
        mock_get_client.return_value = mock_client

        result = evaluate_storage_encryption(mock_bucket)
        expected = {
            'BucketLocation': 'europe-west1',
            'Algorithm': 'AES-256',
            'Key': 'Google Managed',
            'KeyLocation': 'europe-west1'
        }
        self.assertEqual(result, expected)

    @patch("havik.gcp.storage.get_client")
    def test_evaluate_storage_public_access(self, mock_get_client):
        mock_bucket = MagicMock()
        mock_bucket.iam_configuration.public_access_prevention = "enforced"

        mock_client = MagicMock()
        mock_client.get_bucket.return_value = mock_bucket
        mock_get_client.return_value = mock_client

        result = evaluate_storage_public_access(mock_bucket)
        self.assertEqual(result["Status"], 'Blocked')

    @patch("havik.gcp.storage.get_client")
    def test_list_buckets(self, mock_get_client):
        mock_bucket_1 = MagicMock(name="bucket-a")
        mock_bucket_1.name = "bucket-a"
        mock_bucket_2 = MagicMock(name="bucket-b")
        mock_bucket_2.name = "bucket-b"

        mock_client = MagicMock()
        mock_client.list_buckets.return_value = [mock_bucket_1, mock_bucket_2]
        mock_get_client.return_value = mock_client

        result = list_buckets()
        self.assertEqual(result, [mock_bucket_1, mock_bucket_2])
