"""Tests for distributed pipeline components."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from autosiem.distributed import DistributedConfig, DistributedPipeline, config_from_env
from autosiem.rules import load_rules


class TestDistributedConfig:
    """Tests for DistributedConfig."""

    def test_defaults(self):
        """Default configuration has no distributed features enabled."""
        config = DistributedConfig()
        assert config.queue_path is None
        assert config.archive_path is None
        assert config.workers == 4
        assert config.backend_type == "sqlite"
        assert not config.queue_enabled
        assert not config.archive_enabled
        assert config.parallel_enabled  # workers > 1

    def test_queue_enabled_when_path_set(self):
        """Queue is enabled when path is configured."""
        config = DistributedConfig(queue_path="/tmp/queue.db")
        assert config.queue_enabled

    def test_archive_enabled_when_path_set(self):
        """Archive is enabled when path is configured."""
        config = DistributedConfig(archive_path="/tmp/archive.jsonl")
        assert config.archive_enabled

    def test_config_from_env_reads_environment(self, monkeypatch):
        """config_from_env reads from environment variables."""
        monkeypatch.setenv("AUTOSIEM_QUEUE_PATH", "/tmp/test_queue.db")
        monkeypatch.setenv("AUTOSIEM_QUEUE_MAX_PENDING", "5000")
        monkeypatch.setenv("AUTOSIEM_ARCHIVE_PATH", "/tmp/test_archive.jsonl")
        monkeypatch.setenv("AUTOSIEM_WORKERS", "8")
        monkeypatch.setenv("AUTOSIEM_BACKEND", "clickhouse")
        monkeypatch.setenv("AUTOSIEM_BACKEND_URL", "http://localhost:8123")

        config = config_from_env()
        assert config.queue_path == "/tmp/test_queue.db"
        assert config.queue_max_pending == 5000
        assert config.archive_path == "/tmp/test_archive.jsonl"
        assert config.workers == 8
        assert config.backend_type == "clickhouse"
        assert config.backend_url == "http://localhost:8123"


class TestDistributedPipeline:
    """Tests for DistributedPipeline."""

    @pytest.fixture
    def temp_dir(self, tmp_path):
        """Create a temporary directory for test files."""
        return tmp_path

    @pytest.fixture
    def sample_lines(self):
        """Sample JSONL event lines."""
        return [
            json.dumps({"timestamp": "2026-08-06T10:00:00Z", "category": "authentication", "action": "login_failed", "user": "alice", "src_ip": "198.51.100.25", "outcome": "failure"}),
            json.dumps({"timestamp": "2026-08-06T10:01:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "powershell.exe", "command_line": "powershell -enc ABC", "outcome": "success"}),
        ]

    def test_process_lines_without_distributed_features(self, temp_dir, sample_lines):
        """Processing works without any distributed features enabled."""
        config = DistributedConfig(workers=1)  # Disable parallel processing for deterministic test
        rules = load_rules(Path(__file__).parent.parent / "rules")
        
        pipeline = DistributedPipeline(config, rules, db_path=str(temp_dir / "test.db"))
        result = pipeline.process_lines(sample_lines)
        
        assert result["events"] == 2
        assert result["findings"] >= 0  # Depends on rules matching
        assert "incidents" in result

    def test_process_lines_with_archive(self, temp_dir, sample_lines):
        """Archive writes events to journal file."""
        archive_path = str(temp_dir / "archive.jsonl")
        config = DistributedConfig(archive_path=archive_path, workers=1)
        rules = load_rules(Path(__file__).parent.parent / "rules")
        
        pipeline = DistributedPipeline(config, rules, db_path=str(temp_dir / "test.db"))
        result = pipeline.process_lines(sample_lines)
        
        assert result["events"] == 2
        # Verify archive was created and has entries
        assert Path(archive_path).exists()
        with open(archive_path) as f:
            lines = f.readlines()
        assert len(lines) == 2

    def test_process_lines_with_queue(self, temp_dir, sample_lines):
        """Queue stores events for backpressure."""
        queue_path = str(temp_dir / "queue.db")
        config = DistributedConfig(queue_path=queue_path, queue_max_pending=100, workers=1)
        rules = load_rules(Path(__file__).parent.parent / "rules")
        
        pipeline = DistributedPipeline(config, rules, db_path=str(temp_dir / "test.db"))
        result = pipeline.process_lines(sample_lines)
        
        assert result["events"] == 2
        # Queue stats should be available
        stats = pipeline.stats
        assert "queue_pending" in stats or "queue_total" in stats

    def test_replay_from_empty_queue(self, temp_dir):
        """Replay returns empty result when queue has no pending messages."""
        queue_path = str(temp_dir / "queue.db")
        config = DistributedConfig(queue_path=queue_path, workers=1)
        rules = load_rules(Path(__file__).parent.parent / "rules")
        
        pipeline = DistributedPipeline(config, rules, db_path=str(temp_dir / "test.db"))
        result = pipeline.replay_from_queue()
        
        assert result["replayed"] == 0
        assert result["events"] == 0

    def test_stats_returns_queue_and_archive_info(self, temp_dir, sample_lines):
        """Stats returns information about queue and archive state."""
        queue_path = str(temp_dir / "queue.db")
        archive_path = str(temp_dir / "archive.jsonl")
        config = DistributedConfig(queue_path=queue_path, archive_path=archive_path, workers=1)
        rules = load_rules(Path(__file__).parent.parent / "rules")
        
        pipeline = DistributedPipeline(config, rules, db_path=str(temp_dir / "test.db"))
        pipeline.process_lines(sample_lines)
        
        stats = pipeline.stats
        assert "archive_sequence" in stats
        assert stats["archive_sequence"] == 2

    def test_parallel_processing_with_workers(self, temp_dir, sample_lines):
        """Parallel processing with worker pool produces same results."""
        config = DistributedConfig(workers=4)  # Enable parallel
        rules = load_rules(Path(__file__).parent.parent / "rules")
        
        pipeline = DistributedPipeline(config, rules, db_path=str(temp_dir / "test.db"))
        result = pipeline.process_lines(sample_lines)
        
        assert result["events"] == 2

    def test_empty_lines_returns_empty_result(self, temp_dir):
        """Empty input returns empty result."""
        config = DistributedConfig(workers=1)
        rules = load_rules(Path(__file__).parent.parent / "rules")
        
        pipeline = DistributedPipeline(config, rules, db_path=str(temp_dir / "test.db"))
        result = pipeline.process_lines([])
        
        assert result["events"] == 0
        assert result["findings"] == 0
        assert result["incidents"] == 0
