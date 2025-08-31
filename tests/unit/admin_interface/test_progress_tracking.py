# Progress Tracking Unit Tests
# Tests for real-time progress tracking during system assessment

import pytest
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import queue
import json

class TestProgressTracking:
    """Unit tests for progress tracking functionality."""
    
    @pytest.fixture
    def mock_progress_data(self):
        """Mock progress tracking data for testing."""
        return {
            "assessment_id": "assessment_20250830_100000",
            "total_steps": 6,
            "completed_steps": 0,
            "current_step": "B001_registry_modification",
            "step_details": {
                "B001_registry_modification": {"name": "Registry Analysis", "estimated_seconds": 8},
                "B002_user_account_security": {"name": "User Account Analysis", "estimated_seconds": 6},
                "B003_group_policy_compliance": {"name": "Group Policy Analysis", "estimated_seconds": 10},
                "B004_system_integrity": {"name": "System Integrity Check", "estimated_seconds": 12},
                "B005_network_configuration": {"name": "Network Analysis", "estimated_seconds": 7},
                "B006_time_control_bypass": {"name": "Time Control Analysis", "estimated_seconds": 5}
            },
            "start_time": datetime.now().isoformat(),
            "current_status": "Starting system security assessment...",
            "progress_percentage": 0.0,
            "estimated_completion": None,
            "error_state": False,
            "error_message": None
        }

    @pytest.fixture 
    def mock_progress_queue(self):
        """Mock progress message queue for testing."""
        return queue.Queue()

    def test_progress_tracker_initialization(self):
        """Test progress tracker initialization."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        
        assert tracker is not None
        assert hasattr(tracker, 'start_tracking')
        assert hasattr(tracker, 'update_progress')
        assert hasattr(tracker, 'get_current_status')
        assert hasattr(tracker, 'stop_tracking')

    def test_progress_tracking_start(self, mock_progress_data):
        """Test starting progress tracking."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        assert session_id is not None
        assert isinstance(session_id, str)
        assert len(session_id) > 0
        
        # Verify initial state is set
        current_status = tracker.get_current_status(session_id)
        assert current_status['completed_steps'] == 0
        assert current_status['progress_percentage'] == 0.0
        assert current_status['error_state'] == False

    def test_progress_step_completion(self, mock_progress_data):
        """Test marking steps as completed and updating progress."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Complete first step
        update_data = {
            "completed_steps": 1,
            "current_step": "B002_user_account_security", 
            "current_status": "Analyzing user accounts...",
            "step_results": {
                "B001_registry_modification": {"status": "completed", "findings": 3}
            }
        }
        
        tracker.update_progress(session_id, update_data)
        
        current_status = tracker.get_current_status(session_id)
        assert current_status['completed_steps'] == 1
        assert current_status['current_step'] == "B002_user_account_security"
        assert abs(current_status['progress_percentage'] - 16.67) < 0.1  # 1/6 = ~16.67%

    def test_progress_percentage_calculation(self, mock_progress_data):
        """Test accurate progress percentage calculation."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Test various completion states
        test_cases = [
            {"completed": 0, "total": 6, "expected": 0.0},
            {"completed": 1, "total": 6, "expected": 16.67},
            {"completed": 3, "total": 6, "expected": 50.0},
            {"completed": 6, "total": 6, "expected": 100.0}
        ]
        
        for test_case in test_cases:
            percentage = tracker.calculate_progress_percentage(
                test_case['completed'], 
                test_case['total']
            )
            assert abs(percentage - test_case['expected']) < 0.1

    def test_estimated_completion_time(self, mock_progress_data):
        """Test estimated completion time calculation."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Simulate time passage and step completion
        start_time = datetime.now()
        
        # Complete 2 steps after 15 seconds
        elapsed_time = 15  # seconds
        completed_steps = 2
        total_steps = 6
        
        estimated_completion = tracker.calculate_estimated_completion(
            start_time, elapsed_time, completed_steps, total_steps
        )
        
        assert estimated_completion is not None
        assert isinstance(estimated_completion, datetime)
        
        # Should estimate ~30 more seconds (15 seconds / 2 steps = 7.5 seconds per step * 4 remaining)
        expected_completion = start_time + timedelta(seconds=45)  # 15 + 30
        time_diff = abs((estimated_completion - expected_completion).total_seconds())
        assert time_diff < 5  # Within 5 seconds tolerance

    def test_progress_error_handling(self, mock_progress_data):
        """Test error state handling in progress tracking."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Simulate error during step execution
        error_update = {
            "error_state": True,
            "error_message": "PowerShell script failed: Access denied",
            "error_step": "B001_registry_modification",
            "error_details": {
                "error_type": "ACCESS_DENIED",
                "recovery_suggestions": ["Run as Administrator", "Check permissions"]
            }
        }
        
        tracker.update_progress(session_id, error_update)
        
        current_status = tracker.get_current_status(session_id)
        assert current_status['error_state'] == True
        assert current_status['error_message'] == error_update['error_message']
        assert 'error_details' in current_status

    def test_progress_cancellation(self, mock_progress_data):
        """Test progress tracking cancellation."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Cancel progress tracking
        cancellation_result = tracker.cancel_tracking(session_id)
        
        assert cancellation_result == True
        
        current_status = tracker.get_current_status(session_id)
        assert current_status['status'] == 'cancelled'
        assert current_status['cancellation_time'] is not None

    def test_concurrent_progress_sessions(self, mock_progress_data):
        """Test handling multiple concurrent progress tracking sessions."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        
        # Start multiple sessions
        session1_data = mock_progress_data.copy()
        session1_data['assessment_id'] = "assessment_1"
        
        session2_data = mock_progress_data.copy()
        session2_data['assessment_id'] = "assessment_2"
        
        session1_id = tracker.start_tracking(session1_data)
        session2_id = tracker.start_tracking(session2_data)
        
        assert session1_id != session2_id
        
        # Update each session independently
        tracker.update_progress(session1_id, {"completed_steps": 1})
        tracker.update_progress(session2_id, {"completed_steps": 2})
        
        status1 = tracker.get_current_status(session1_id)
        status2 = tracker.get_current_status(session2_id)
        
        assert status1['completed_steps'] == 1
        assert status2['completed_steps'] == 2

    def test_progress_persistence(self, mock_progress_data, tmp_path):
        """Test progress state persistence to disk."""
        from src.admin_interface.components.progress import ProgressTracker
        
        progress_file = tmp_path / "progress_state.json"
        
        tracker = ProgressTracker(persistence_file=str(progress_file))
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Update progress
        tracker.update_progress(session_id, {"completed_steps": 3})
        
        # Save state
        tracker.save_state()
        
        # Verify file exists and contains data
        assert progress_file.exists()
        
        with open(progress_file, 'r') as f:
            saved_data = json.load(f)
            
        assert session_id in saved_data
        assert saved_data[session_id]['completed_steps'] == 3

    def test_progress_state_recovery(self, mock_progress_data, tmp_path):
        """Test recovery of progress state from disk."""
        from src.admin_interface.components.progress import ProgressTracker
        
        progress_file = tmp_path / "progress_state.json"
        
        # Create initial tracker and save state
        tracker1 = ProgressTracker(persistence_file=str(progress_file))
        session_id = tracker1.start_tracking(mock_progress_data)
        tracker1.update_progress(session_id, {"completed_steps": 2})
        tracker1.save_state()
        
        # Create new tracker and load state
        tracker2 = ProgressTracker(persistence_file=str(progress_file))
        tracker2.load_state()
        
        # Verify state recovery
        recovered_status = tracker2.get_current_status(session_id)
        assert recovered_status is not None
        assert recovered_status['completed_steps'] == 2

    def test_progress_event_callbacks(self, mock_progress_data):
        """Test progress event callback functionality."""
        from src.admin_interface.components.progress import ProgressTracker
        
        callback_events = []
        
        def progress_callback(event_type, session_id, data):
            callback_events.append({
                'event_type': event_type,
                'session_id': session_id,
                'data': data
            })
        
        tracker = ProgressTracker()
        tracker.register_callback('progress_update', progress_callback)
        
        session_id = tracker.start_tracking(mock_progress_data)
        tracker.update_progress(session_id, {"completed_steps": 1})
        
        # Verify callbacks were triggered
        assert len(callback_events) >= 1
        
        progress_events = [e for e in callback_events if e['event_type'] == 'progress_update']
        assert len(progress_events) > 0

    def test_progress_metrics_collection(self, mock_progress_data):
        """Test collection of progress metrics for performance analysis."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Simulate step completions with timing
        step_timings = [
            {"step": "B001_registry_modification", "duration": 8.2},
            {"step": "B002_user_account_security", "duration": 6.8},
            {"step": "B003_group_policy_compliance", "duration": 11.5}
        ]
        
        for timing in step_timings:
            tracker.record_step_timing(session_id, timing['step'], timing['duration'])
        
        metrics = tracker.get_performance_metrics(session_id)
        
        assert 'average_step_duration' in metrics
        assert 'total_elapsed_time' in metrics
        assert 'step_timings' in metrics
        assert len(metrics['step_timings']) == 3

    def test_progress_ui_integration(self):
        """Test integration with Streamlit UI components."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        
        # Test UI data formatting
        progress_data = {
            "completed_steps": 3,
            "total_steps": 6,
            "current_status": "Analyzing network configuration...",
            "progress_percentage": 50.0
        }
        
        ui_data = tracker.format_for_ui(progress_data)
        
        assert 'progress_bar_value' in ui_data
        assert 'status_text' in ui_data
        assert 'completion_percentage' in ui_data
        assert ui_data['progress_bar_value'] == 0.5  # 50% as decimal

    def test_progress_cleanup(self, mock_progress_data):
        """Test proper cleanup of completed progress sessions."""
        from src.admin_interface.components.progress import ProgressTracker
        
        tracker = ProgressTracker()
        session_id = tracker.start_tracking(mock_progress_data)
        
        # Complete all steps
        tracker.update_progress(session_id, {
            "completed_steps": 6,
            "progress_percentage": 100.0,
            "status": "completed"
        })
        
        # Cleanup completed session
        cleanup_result = tracker.cleanup_completed_sessions()
        
        assert cleanup_result >= 1  # At least one session cleaned up
        
        # Verify session is cleaned up (should return None or empty)
        status = tracker.get_current_status(session_id)
        assert status is None or status.get('status') == 'cleaned_up'