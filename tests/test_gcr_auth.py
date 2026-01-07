"""Tests for GCR authentication module."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from utils.gcr_auth import GCRAuthenticator, GCR_REGISTRY_PATTERNS, ARTIFACT_REGISTRY_SUFFIX


class TestGCRAuthenticatorRegistryDetection:
    """Tests for GCR registry detection."""

    def test_is_gcr_registry_gcr_io(self):
        """Test detection of gcr.io registry."""
        auth = GCRAuthenticator()
        assert auth.is_gcr_registry("gcr.io/my-project/my-image:latest") is True

    def test_is_gcr_registry_regional(self):
        """Test detection of regional GCR registries."""
        auth = GCRAuthenticator()
        assert auth.is_gcr_registry("us.gcr.io/my-project/my-image:latest") is True
        assert auth.is_gcr_registry("eu.gcr.io/my-project/my-image:latest") is True
        assert auth.is_gcr_registry("asia.gcr.io/my-project/my-image:latest") is True

    def test_is_gcr_registry_artifact_registry(self):
        """Test detection of Artifact Registry."""
        auth = GCRAuthenticator()
        assert auth.is_gcr_registry("us-docker.pkg.dev/my-project/my-repo/my-image:latest") is True
        assert auth.is_gcr_registry("europe-docker.pkg.dev/my-project/my-repo/my-image:latest") is True

    def test_is_gcr_registry_mirror(self):
        """Test that public mirror doesn't require auth."""
        auth = GCRAuthenticator()
        assert auth.is_gcr_registry("mirror.gcr.io/library/nginx:latest") is False

    def test_is_gcr_registry_non_gcr(self):
        """Test non-GCR registries return False."""
        auth = GCRAuthenticator()
        assert auth.is_gcr_registry("docker.io/library/nginx:latest") is False
        assert auth.is_gcr_registry("quay.io/myorg/myimage:latest") is False
        assert auth.is_gcr_registry("ghcr.io/myorg/myimage:latest") is False
        assert auth.is_gcr_registry("cgr.dev/chainguard/python:latest") is False

    def test_is_gcr_registry_empty(self):
        """Test empty/None image returns False."""
        auth = GCRAuthenticator()
        assert auth.is_gcr_registry("") is False
        assert auth.is_gcr_registry(None) is False


class TestGCRAuthenticatorCredentials:
    """Tests for credential handling."""

    def test_init_with_credentials_file(self):
        """Test initialization with credentials file."""
        creds_path = Path("/path/to/credentials.json")
        auth = GCRAuthenticator(credentials_file=creds_path)
        assert auth.credentials_file == creds_path

    def test_init_without_credentials_file(self):
        """Test initialization without credentials file."""
        auth = GCRAuthenticator()
        assert auth.credentials_file is None


class TestGCRAuthenticatorServiceAccount:
    """Tests for service account authentication."""

    def test_auth_with_valid_service_account(self):
        """Test authentication with valid service account JSON."""
        auth = GCRAuthenticator()

        # Create temporary credentials file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "type": "service_account",
                "client_email": "test@test-project.iam.gserviceaccount.com",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...fake...\n-----END PRIVATE KEY-----\n",
                "token_uri": "https://oauth2.googleapis.com/token"
            }, f)
            creds_file = Path(f.name)

        try:
            with patch('subprocess.run') as mock_run:
                # Mock successful gcloud activation
                mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

                result = auth._auth_with_service_account(creds_file)

                # Should call gcloud auth activate-service-account
                assert mock_run.called
        finally:
            creds_file.unlink()

    def test_auth_with_invalid_json(self):
        """Test authentication fails with invalid JSON."""
        auth = GCRAuthenticator()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json")
            creds_file = Path(f.name)

        try:
            result = auth._auth_with_service_account(creds_file)
            assert result is False
        finally:
            creds_file.unlink()

    def test_auth_with_missing_fields(self):
        """Test authentication fails with missing required fields."""
        auth = GCRAuthenticator()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"type": "service_account"}, f)  # Missing client_email and private_key
            creds_file = Path(f.name)

        try:
            result = auth._auth_with_service_account(creds_file)
            assert result is False
        finally:
            creds_file.unlink()

    def test_auth_with_nonexistent_file(self):
        """Test authentication fails with nonexistent file."""
        auth = GCRAuthenticator()
        result = auth._auth_with_service_account(Path("/nonexistent/path.json"))
        assert result is False


class TestGCRAuthenticatorGcloudADC:
    """Tests for gcloud ADC authentication."""

    def test_auth_with_gcloud_adc_success(self):
        """Test successful gcloud ADC authentication."""
        auth = GCRAuthenticator()

        with patch('subprocess.run') as mock_run:
            # Mock successful gcloud version check
            mock_run.side_effect = [
                MagicMock(returncode=0),  # gcloud version
                MagicMock(returncode=0, stdout="ya29.fake-token\n", stderr=""),  # gcloud auth print-access-token
                MagicMock(returncode=0),  # docker login gcr.io
                MagicMock(returncode=0),  # docker login us.gcr.io
                MagicMock(returncode=0),  # docker login eu.gcr.io
                MagicMock(returncode=0),  # docker login asia.gcr.io
                MagicMock(returncode=0),  # docker login pkg.dev
            ]

            result = auth._auth_with_gcloud_adc()
            assert result is True

    def test_auth_with_gcloud_not_installed(self):
        """Test authentication fails when gcloud not installed."""
        auth = GCRAuthenticator()

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("gcloud not found")

            result = auth._auth_with_gcloud_adc()
            assert result is False

    def test_auth_with_gcloud_not_logged_in(self):
        """Test authentication fails when gcloud not logged in."""
        auth = GCRAuthenticator()

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0),  # gcloud version
                MagicMock(returncode=1, stdout="", stderr="not logged in"),  # gcloud auth print-access-token
            ]

            result = auth._auth_with_gcloud_adc()
            assert result is False


class TestGCRAuthenticatorAuthenticate:
    """Tests for the main authenticate method."""

    def test_authenticate_priority_cli_flag(self):
        """Test CLI flag takes priority over env var."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "type": "service_account",
                "client_email": "cli@test.iam.gserviceaccount.com",
                "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
            }, f)
            cli_creds = Path(f.name)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "type": "service_account",
                "client_email": "env@test.iam.gserviceaccount.com",
                "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
            }, f)
            env_creds = f.name

        try:
            # Set env var
            old_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = env_creds

            auth = GCRAuthenticator(credentials_file=cli_creds)

            with patch.object(auth, '_auth_with_service_account') as mock_auth:
                mock_auth.return_value = True

                auth.authenticate()

                # Should use CLI flag path, not env var path
                mock_auth.assert_called_once_with(cli_creds)

        finally:
            cli_creds.unlink()
            Path(env_creds).unlink()
            if old_env is not None:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = old_env
            elif "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
                del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]

    def test_authenticate_priority_env_var(self):
        """Test env var is used when no CLI flag provided."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "type": "service_account",
                "client_email": "env@test.iam.gserviceaccount.com",
                "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
            }, f)
            env_creds = f.name

        try:
            old_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = env_creds

            auth = GCRAuthenticator()  # No CLI flag

            with patch.object(auth, '_auth_with_service_account') as mock_auth:
                mock_auth.return_value = True

                auth.authenticate()

                mock_auth.assert_called_once_with(Path(env_creds))

        finally:
            Path(env_creds).unlink()
            if old_env is not None:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = old_env
            elif "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
                del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]

    def test_authenticate_fallback_to_adc(self):
        """Test fallback to gcloud ADC when no credentials provided."""
        old_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
            del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]

        try:
            auth = GCRAuthenticator()  # No CLI flag

            with patch.object(auth, '_auth_with_gcloud_adc') as mock_adc:
                mock_adc.return_value = True

                result = auth.authenticate()

                assert result is True
                mock_adc.assert_called_once()

        finally:
            if old_env is not None:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = old_env

    def test_authenticate_all_methods_fail(self):
        """Test authenticate returns False when all methods fail."""
        old_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
            del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]

        try:
            auth = GCRAuthenticator()

            with patch.object(auth, '_auth_with_gcloud_adc') as mock_adc:
                mock_adc.return_value = False

                result = auth.authenticate()

                assert result is False

        finally:
            if old_env is not None:
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = old_env


class TestGCRAuthenticatorDockerCredentials:
    """Tests for Docker credential configuration."""

    def test_configure_docker_credentials_success(self):
        """Test successful Docker credential configuration."""
        auth = GCRAuthenticator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = auth._configure_docker_credentials("ya29.fake-token")

            assert result is True
            # Should attempt to configure all GCR registries
            assert mock_run.call_count >= len(GCR_REGISTRY_PATTERNS)

    def test_configure_docker_credentials_partial_failure(self):
        """Test Docker config succeeds if at least one registry works."""
        auth = GCRAuthenticator()

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return MagicMock(returncode=1, stderr="failed")
            return MagicMock(returncode=0)

        with patch('subprocess.run', side_effect=side_effect):
            result = auth._configure_docker_credentials("ya29.fake-token")
            assert result is True  # At least one succeeded


class TestGetAccessToken:
    """Tests for access token retrieval."""

    def test_get_access_token_success(self):
        """Test successful access token retrieval."""
        auth = GCRAuthenticator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="ya29.test-access-token\n"
            )

            token = auth.get_access_token()

            assert token == "ya29.test-access-token"

    def test_get_access_token_failure(self):
        """Test access token retrieval failure."""
        auth = GCRAuthenticator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")

            token = auth.get_access_token()

            assert token is None

    def test_get_access_token_gcloud_not_installed(self):
        """Test access token retrieval when gcloud not installed."""
        auth = GCRAuthenticator()

        with patch('subprocess.run', side_effect=FileNotFoundError("gcloud not found")):
            token = auth.get_access_token()
            assert token is None
