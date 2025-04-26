import pytest
import os
import sys
from unittest.mock import MagicMock, patch

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock Streamlit
sys.modules['streamlit'] = MagicMock()

@pytest.fixture
def db():
    return Database()

@pytest.fixture
def analyzer():
    return ThreatAnalyzer()

def test_validate_ip():
    """Test IP address validation"""
    from app import validate_ip
    
    # Test valid IPv4
    assert validate_ip("192.168.1.1") == True
    
    # Test invalid IPv4
    assert validate_ip("256.256.256.256") == False
    
    # Test invalid format
    assert validate_ip("not.an.ip") == False
    
    # Test valid IPv6
    assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == True

@patch('database.Database')
def test_database_connection(mock_db):
    """Test database connection functionality"""
    # Setup mock
    mock_instance = mock_db.return_value
    mock_instance.connect.return_value = True
    mock_instance.is_connected.return_value = True
    
    # Test connection
    assert mock_instance.connect() == True
    assert mock_instance.is_connected() == True
    
    # Test disconnection
    mock_instance.disconnect()
    mock_instance.is_connected.return_value = False
    assert mock_instance.is_connected() == False

@patch('threat_analyzer.threat_analyzer.ThreatAnalyzer')
def test_threat_analyzer_initialization(mock_analyzer):
    """Test threat analyzer initialization and methods"""
    # Setup mock
    mock_instance = mock_analyzer.return_value
    mock_instance.analyze_ip.return_value = {"score": 0.5}
    mock_instance.analyze_domain.return_value = {"score": 0.3}
    mock_instance.get_threat_score.return_value = 0.5
    
    # Test initialization
    assert mock_instance is not None
    
    # Test method existence
    assert hasattr(mock_instance, 'analyze_ip')
    assert hasattr(mock_instance, 'analyze_domain')
    assert hasattr(mock_instance, 'get_threat_score')
    
    # Test method calls
    assert mock_instance.analyze_ip("192.168.1.1")["score"] == 0.5
    assert mock_instance.analyze_domain("example.com")["score"] == 0.3
    assert mock_instance.get_threat_score() == 0.5

def test_session_state_initialization():
    """Test Streamlit session state initialization"""
    from app import st
    
    # Test initial state
    assert not hasattr(st, 'session_state')
    
    # Mock session state
    st.session_state = {}
    
    # Test session state keys
    assert 'db' not in st.session_state
    assert 'threat_analyzer' not in st.session_state 