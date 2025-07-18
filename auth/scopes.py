"""
Google Workspace OAuth Scopes

This module centralizes OAuth scope definitions for Google Workspace integration.
Separated from service_decorator.py to avoid circular imports.
"""
import logging
from typing import Dict, Optional, NamedTuple

logger = logging.getLogger(__name__)

# OAuth state info structure
class OAuthStateInfo(NamedTuple):
    session_id: Optional[str]
    client_id: Optional[str]
    client_secret: Optional[str]

# Temporary map to associate OAuth state with session info and credentials
# This should ideally be a more robust cache in a production system (e.g., Redis)
OAUTH_STATE_TO_SESSION_INFO_MAP: Dict[str, OAuthStateInfo] = {}

# Legacy map for backward compatibility
OAUTH_STATE_TO_SESSION_ID_MAP: Dict[str, str] = {}

# Import Redis store functions
try:
    from auth.redis_state_store import get_redis_store
    _redis_available = True
except ImportError:
    logger.warning("Redis state store not available, using in-memory storage only")
    _redis_available = False

# Individual OAuth Scope Constants
USERINFO_EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'
OPENID_SCOPE = 'openid'
CALENDAR_READONLY_SCOPE = 'https://www.googleapis.com/auth/calendar.readonly'
CALENDAR_EVENTS_SCOPE = 'https://www.googleapis.com/auth/calendar.events'

# Google Drive scopes
DRIVE_READONLY_SCOPE = 'https://www.googleapis.com/auth/drive.readonly'
DRIVE_FILE_SCOPE = 'https://www.googleapis.com/auth/drive.file'

# Google Docs scopes
DOCS_READONLY_SCOPE = 'https://www.googleapis.com/auth/documents.readonly'
DOCS_WRITE_SCOPE = 'https://www.googleapis.com/auth/documents'

# Gmail API scopes
GMAIL_READONLY_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly'
GMAIL_SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send'
GMAIL_COMPOSE_SCOPE = 'https://www.googleapis.com/auth/gmail.compose'
GMAIL_MODIFY_SCOPE = 'https://www.googleapis.com/auth/gmail.modify'
GMAIL_LABELS_SCOPE = 'https://www.googleapis.com/auth/gmail.labels'

# Google Chat API scopes
CHAT_READONLY_SCOPE = 'https://www.googleapis.com/auth/chat.messages.readonly'
CHAT_WRITE_SCOPE = 'https://www.googleapis.com/auth/chat.messages'
CHAT_SPACES_SCOPE = 'https://www.googleapis.com/auth/chat.spaces'

# Google Sheets API scopes
SHEETS_READONLY_SCOPE = 'https://www.googleapis.com/auth/spreadsheets.readonly'
SHEETS_WRITE_SCOPE = 'https://www.googleapis.com/auth/spreadsheets'

# Google Forms API scopes
FORMS_BODY_SCOPE = 'https://www.googleapis.com/auth/forms.body'
FORMS_BODY_READONLY_SCOPE = 'https://www.googleapis.com/auth/forms.body.readonly'
FORMS_RESPONSES_READONLY_SCOPE = 'https://www.googleapis.com/auth/forms.responses.readonly'

# Google Slides API scopes
SLIDES_SCOPE = 'https://www.googleapis.com/auth/presentations'
SLIDES_READONLY_SCOPE = 'https://www.googleapis.com/auth/presentations.readonly'

# Google Tasks API scopes
TASKS_SCOPE = 'https://www.googleapis.com/auth/tasks'
TASKS_READONLY_SCOPE = 'https://www.googleapis.com/auth/tasks.readonly'

# Base OAuth scopes required for user identification
BASE_SCOPES = [
    USERINFO_EMAIL_SCOPE,
    OPENID_SCOPE
]

# Service-specific scope groups
DOCS_SCOPES = [
    DOCS_READONLY_SCOPE,
    DOCS_WRITE_SCOPE
]

CALENDAR_SCOPES = [
    CALENDAR_READONLY_SCOPE,
    CALENDAR_EVENTS_SCOPE
]

DRIVE_SCOPES = [
    DRIVE_READONLY_SCOPE,
    DRIVE_FILE_SCOPE
]

GMAIL_SCOPES = [
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_LABELS_SCOPE
]

CHAT_SCOPES = [
    CHAT_READONLY_SCOPE,
    CHAT_WRITE_SCOPE,
    CHAT_SPACES_SCOPE
]

SHEETS_SCOPES = [
    SHEETS_READONLY_SCOPE,
    SHEETS_WRITE_SCOPE
]

FORMS_SCOPES = [
    FORMS_BODY_SCOPE,
    FORMS_BODY_READONLY_SCOPE,
    FORMS_RESPONSES_READONLY_SCOPE
]

SLIDES_SCOPES = [
    SLIDES_SCOPE,
    SLIDES_READONLY_SCOPE
]

TASKS_SCOPES = [
    TASKS_SCOPE,
    TASKS_READONLY_SCOPE
]

# Combined scopes for all supported Google Workspace operations
SCOPES = list(set(BASE_SCOPES + CALENDAR_SCOPES + DRIVE_SCOPES + GMAIL_SCOPES + DOCS_SCOPES + CHAT_SCOPES + SHEETS_SCOPES + FORMS_SCOPES + SLIDES_SCOPES + TASKS_SCOPES))


# Helper functions for state management with Redis fallback
def store_oauth_state(state: str, session_id: Optional[str], 
                     client_id: Optional[str], client_secret: Optional[str]) -> None:
    """
    Store OAuth state with Redis fallback to in-memory.
    
    Args:
        state: OAuth state parameter
        session_id: MCP session ID
        client_id: OAuth client ID
        client_secret: OAuth client secret
    """
    # Try Redis first
    if _redis_available:
        try:
            redis_store = get_redis_store()
            if redis_store.store_oauth_state(state, session_id, client_id, client_secret):
                logger.debug(f"Stored OAuth state in Redis: {state}")
                return
        except Exception as e:
            logger.warning(f"Failed to store in Redis, falling back to memory: {e}")
    
    # Fallback to in-memory
    state_info = OAuthStateInfo(session_id=session_id, client_id=client_id, client_secret=client_secret)
    OAUTH_STATE_TO_SESSION_INFO_MAP[state] = state_info
    
    # Also update legacy map for backward compatibility
    if session_id:
        OAUTH_STATE_TO_SESSION_ID_MAP[state] = session_id
    
    logger.debug(f"Stored OAuth state in memory: {state}")


def get_oauth_state(state: str) -> Optional[OAuthStateInfo]:
    """
    Retrieve OAuth state with Redis fallback to in-memory.
    
    Args:
        state: OAuth state parameter
        
    Returns:
        OAuthStateInfo or None
    """
    # Try Redis first
    if _redis_available:
        try:
            redis_store = get_redis_store()
            data = redis_store.get_oauth_state(state)
            if data:
                logger.debug(f"Retrieved OAuth state from Redis: {state}")
                return OAuthStateInfo(
                    session_id=data.get("session_id"),
                    client_id=data.get("client_id"),
                    client_secret=data.get("client_secret")
                )
        except Exception as e:
            logger.warning(f"Failed to retrieve from Redis, falling back to memory: {e}")
    
    # Try in-memory map
    state_info = OAUTH_STATE_TO_SESSION_INFO_MAP.pop(state, None)
    if state_info:
        logger.debug(f"Retrieved OAuth state from memory: {state}")
        return state_info
    
    # Try legacy map as last resort
    session_id = OAUTH_STATE_TO_SESSION_ID_MAP.pop(state, None)
    if session_id:
        logger.debug(f"Retrieved session ID from legacy map: {state}")
        return OAuthStateInfo(session_id=session_id, client_id=None, client_secret=None)
    
    return None