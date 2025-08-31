# Progress Tracking Component for Admin Interface
# Real-time progress tracking during system assessment

import time
import threading
import queue
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
import os

@dataclass
class ProgressState:
    """Progress tracking state data structure."""
    session_id: str
    assessment_id: str
    total_steps: int
    completed_steps: int
    current_step: str
    current_status: str
    progress_percentage: float
    start_time: datetime
    estimated_completion: Optional[datetime]
    error_state: bool
    error_message: Optional[str]
    step_results: Dict[str, Any]
    step_timings: Dict[str, float]

class ProgressTracker:
    """Real-time progress tracking for system assessments."""
    
    def __init__(self, persistence_file: Optional[str] = None):
        """Initialize progress tracker."""
        self.active_sessions: Dict[str, ProgressState] = {}
        self.callbacks: Dict[str, List[Callable]] = {}
        self.persistence_file = persistence_file
        self._lock = threading.Lock()
        
        # Load existing state if persistence is enabled
        if self.persistence_file and os.path.exists(self.persistence_file):
            self.load_state()
    
    def start_tracking(self, progress_data: Dict[str, Any]) -> str:
        """Start progress tracking for a new assessment."""
        session_id = str(uuid.uuid4())
        
        progress_state = ProgressState(
            session_id=session_id,
            assessment_id=progress_data.get('assessment_id', f"assessment_{int(time.time())}"),
            total_steps=progress_data.get('total_steps', 6),
            completed_steps=0,
            current_step=progress_data.get('current_step', 'initializing'),
            current_status=progress_data.get('current_status', 'Starting assessment...'),
            progress_percentage=0.0,
            start_time=datetime.now(),
            estimated_completion=None,
            error_state=False,
            error_message=None,
            step_results={},
            step_timings={}
        )
        
        with self._lock:
            self.active_sessions[session_id] = progress_state
        
        # Trigger callback
        self._trigger_callback('session_started', session_id, asdict(progress_state))
        
        return session_id
    
    def update_progress(self, session_id: str, update_data: Dict[str, Any]) -> bool:
        """Update progress for an active session."""
        with self._lock:
            if session_id not in self.active_sessions:
                return False
            
            state = self.active_sessions[session_id]
            
            # Update fields if provided
            if 'completed_steps' in update_data:
                state.completed_steps = update_data['completed_steps']
                state.progress_percentage = self.calculate_progress_percentage(
                    state.completed_steps, state.total_steps
                )
            
            if 'current_step' in update_data:
                state.current_step = update_data['current_step']
            
            if 'current_status' in update_data:
                state.current_status = update_data['current_status']
            
            if 'error_state' in update_data:
                state.error_state = update_data['error_state']
            
            if 'error_message' in update_data:
                state.error_message = update_data['error_message']
            
            if 'step_results' in update_data:
                state.step_results.update(update_data['step_results'])
            
            # Calculate estimated completion
            if state.completed_steps > 0:
                elapsed_time = (datetime.now() - state.start_time).total_seconds()
                state.estimated_completion = self.calculate_estimated_completion(
                    state.start_time, elapsed_time, state.completed_steps, state.total_steps
                )
        
        # Trigger callback
        self._trigger_callback('progress_update', session_id, asdict(state))
        
        # Save state if persistence is enabled
        if self.persistence_file:
            self.save_state()
        
        return True
    
    def get_current_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current status for a session."""
        with self._lock:
            if session_id not in self.active_sessions:
                return None
            
            return asdict(self.active_sessions[session_id])
    
    def stop_tracking(self, session_id: str) -> bool:
        """Stop tracking for a session."""
        with self._lock:
            if session_id not in self.active_sessions:
                return False
            
            state = self.active_sessions[session_id]
            state.current_status = "Assessment completed"
            state.progress_percentage = 100.0
        
        # Trigger callback
        self._trigger_callback('session_completed', session_id, asdict(state))
        
        return True
    
    def cancel_tracking(self, session_id: str) -> bool:
        """Cancel tracking for a session."""
        with self._lock:
            if session_id not in self.active_sessions:
                return False
            
            state = self.active_sessions[session_id]
            state.current_status = "Assessment cancelled"
            state.error_state = True
            state.error_message = "Assessment was cancelled by user"
            
            # Add cancellation metadata
            cancellation_data = asdict(state)
            cancellation_data['status'] = 'cancelled'
            cancellation_data['cancellation_time'] = datetime.now().isoformat()
        
        # Trigger callback
        self._trigger_callback('session_cancelled', session_id, cancellation_data)
        
        return True
    
    def calculate_progress_percentage(self, completed_steps: int, total_steps: int) -> float:
        """Calculate progress percentage."""
        if total_steps <= 0:
            return 0.0
        
        percentage = (completed_steps / total_steps) * 100.0
        return round(percentage, 2)
    
    def calculate_estimated_completion(self, start_time: datetime, elapsed_seconds: float, 
                                     completed_steps: int, total_steps: int) -> datetime:
        """Calculate estimated completion time."""
        if completed_steps <= 0:
            return start_time + timedelta(minutes=5)  # Default estimate
        
        # Calculate average time per step
        avg_time_per_step = elapsed_seconds / completed_steps
        
        # Estimate remaining time
        remaining_steps = total_steps - completed_steps
        estimated_remaining_seconds = remaining_steps * avg_time_per_step
        
        return datetime.now() + timedelta(seconds=estimated_remaining_seconds)
    
    def record_step_timing(self, session_id: str, step_name: str, duration_seconds: float):
        """Record timing for a completed step."""
        with self._lock:
            if session_id in self.active_sessions:
                self.active_sessions[session_id].step_timings[step_name] = duration_seconds
    
    def get_performance_metrics(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get performance metrics for a session."""
        with self._lock:
            if session_id not in self.active_sessions:
                return None
            
            state = self.active_sessions[session_id]
            elapsed_time = (datetime.now() - state.start_time).total_seconds()
            
            metrics = {
                'total_elapsed_time': elapsed_time,
                'step_timings': state.step_timings,
                'average_step_duration': 0.0,
                'estimated_total_duration': 0.0
            }
            
            # Calculate average step duration
            if state.step_timings:
                metrics['average_step_duration'] = sum(state.step_timings.values()) / len(state.step_timings)
            
            # Estimate total duration
            if state.completed_steps > 0:
                avg_per_step = elapsed_time / state.completed_steps
                metrics['estimated_total_duration'] = avg_per_step * state.total_steps
            
            return metrics
    
    def register_callback(self, event_type: str, callback: Callable):
        """Register callback for progress events."""
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        
        self.callbacks[event_type].append(callback)
    
    def _trigger_callback(self, event_type: str, session_id: str, data: Dict[str, Any]):
        """Trigger callbacks for an event type."""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    callback(event_type, session_id, data)
                except Exception as e:
                    # Log callback error but don't fail progress tracking
                    print(f"Callback error: {e}")
    
    def save_state(self):
        """Save progress state to disk."""
        if not self.persistence_file:
            return
        
        try:
            state_data = {}
            with self._lock:
                for session_id, state in self.active_sessions.items():
                    state_dict = asdict(state)
                    # Convert datetime objects to strings for JSON serialization
                    state_dict['start_time'] = state.start_time.isoformat()
                    if state.estimated_completion:
                        state_dict['estimated_completion'] = state.estimated_completion.isoformat()
                    else:
                        state_dict['estimated_completion'] = None
                    
                    state_data[session_id] = state_dict
            
            with open(self.persistence_file, 'w') as f:
                json.dump(state_data, f, indent=2)
        
        except Exception as e:
            print(f"Failed to save progress state: {e}")
    
    def load_state(self):
        """Load progress state from disk."""
        if not self.persistence_file or not os.path.exists(self.persistence_file):
            return
        
        try:
            with open(self.persistence_file, 'r') as f:
                state_data = json.load(f)
            
            with self._lock:
                for session_id, state_dict in state_data.items():
                    # Convert string timestamps back to datetime objects
                    state_dict['start_time'] = datetime.fromisoformat(state_dict['start_time'])
                    if state_dict['estimated_completion']:
                        state_dict['estimated_completion'] = datetime.fromisoformat(state_dict['estimated_completion'])
                    
                    # Create ProgressState object
                    state = ProgressState(**state_dict)
                    self.active_sessions[session_id] = state
        
        except Exception as e:
            print(f"Failed to load progress state: {e}")
    
    def cleanup_completed_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up old completed sessions."""
        cleanup_count = 0
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        with self._lock:
            sessions_to_remove = []
            
            for session_id, state in self.active_sessions.items():
                # Remove sessions that are completed and old
                if (state.progress_percentage >= 100.0 or state.error_state) and state.start_time < cutoff_time:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del self.active_sessions[session_id]
                cleanup_count += 1
        
        return cleanup_count
    
    def format_for_ui(self, progress_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format progress data for UI display."""
        return {
            'progress_bar_value': progress_data.get('progress_percentage', 0.0) / 100.0,
            'status_text': progress_data.get('current_status', 'Processing...'),
            'completion_percentage': f"{progress_data.get('progress_percentage', 0.0):.1f}%",
            'current_step': progress_data.get('current_step', ''),
            'completed_steps': progress_data.get('completed_steps', 0),
            'total_steps': progress_data.get('total_steps', 0),
            'estimated_completion': progress_data.get('estimated_completion'),
            'error_state': progress_data.get('error_state', False),
            'error_message': progress_data.get('error_message')
        }
    
    def get_all_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get all active tracking sessions."""
        with self._lock:
            return {
                session_id: asdict(state) 
                for session_id, state in self.active_sessions.items()
            }
    
    def get_session_count(self) -> int:
        """Get count of active sessions."""
        with self._lock:
            return len(self.active_sessions)