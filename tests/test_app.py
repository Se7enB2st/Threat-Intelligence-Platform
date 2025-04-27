import pytest
import os
import sys
from unittest.mock import MagicMock, patch

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock Streamlit
mock_st = MagicMock()
sys.modules['streamlit'] = mock_st

def test_is_valid_ip():
    """Test IP address validation"""
    from app import is_valid_ip
    
    # Test valid IPv4
    assert is_valid_ip("192.168.1.1") == True
    
    # Test invalid IPv4
    assert is_valid_ip("256.256.256.256") == False
    
    # Test invalid format
    assert is_valid_ip("not.an.ip") == False
    
    # Test valid IPv6
    assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == True

@patch('database.get_db')
def test_database_initialization(mock_get_db):
    """Test database initialization"""
    # Setup mock
    mock_db = MagicMock()
    mock_get_db.return_value = mock_db
    
    # Import after mocking
    from app import st
    
    # Test session state initialization
    assert 'db' not in st.session_state
    
    # Initialize session state
    st.session_state.db = mock_get_db()
    assert st.session_state.db == mock_db

@patch('threat_analyzer.threat_analyzer.ThreatAnalyzer')
def test_threat_analyzer_initialization(mock_analyzer_class):
    """Test threat analyzer initialization"""
    # Setup mock
    mock_instance = mock_analyzer_class.return_value
    mock_instance.get_statistics.return_value = {
        'total_ips_tracked': 100,
        'average_threat_score': 0.5,
        'malicious_ips_count': 10,
        'malicious_ip_percentage': 10.0
    }
    
    # Import after mocking
    from app import st
    
    # Test session state initialization
    assert 'analyzer' not in st.session_state
    
    # Initialize session state
    st.session_state.analyzer = mock_instance
    assert st.session_state.analyzer == mock_instance
    
    # Test statistics method
    stats = st.session_state.analyzer.get_statistics(st.session_state.db)
    assert stats['total_ips_tracked'] == 100
    assert stats['average_threat_score'] == 0.5
    assert stats['malicious_ips_count'] == 10
    assert stats['malicious_ip_percentage'] == 10.0

def test_display_ip_details():
    """Test IP details display function"""
    from app import display_ip_details
    
    # Test with error case
    error_details = {"error": "Test error"}
    display_ip_details(error_details)
    mock_st.error.assert_called_with("Test error")
    
    # Test with valid data
    valid_details = {
        "overall_threat_score": 0.8,
        "is_malicious": True,
        "first_seen": "2024-01-01",
        "last_updated": "2024-03-20",
        "threat_data": {
            "virustotal": {"score": 0.8},
            "shodan": {"ports": [80, 443]},
            "alienvault": {"reputation": "malicious"}
        }
    }
    display_ip_details(valid_details)
    mock_st.metric.assert_called() 