# GoForward Realtime System Documentation

## Overview

The GoForward realtime system provides comprehensive WebSocket-based real-time communication with channel management, presence tracking, database change streaming, and message broadcasting. It offers both WebSocket connections and HTTP APIs for complete real-time functionality.

## Key Features

- **WebSocket Channels**: Real-time bidirectional communication with automatic connection management
- **Presence Tracking**: Track user online/offline status and custom state across channels
- **Database Change Streaming**: Real-time database change notifications with filtering
- **Message Broadcasting**: Send messages to all subscribers in channels
- **Connection Management**: Automatic connection pooling, cleanup, and metrics
- **Authentication Integration**: JWT-based authentication for secure connections
- **Database Triggers**: Automatic PostgreSQL trigger setup for change notifications
- **Channel Management**: Create, configure, and manage multiple channels with permissions
- **Metrics & Monitoring**: Real-time statistics and connection monitoring

## Realtime Endpoints

### 1. Channel Management

#### Create Channel
```http
POST /realtime/channels
Content-Type: application/json

{
  "name": "chat-room-1",
  "max_subscribers": 1000,
  "require_auth": true,
  "permissions": {
    "read": ["user", "admin"],
    "write": ["user", "admin"],
    "admin": ["admin"]
  },
  "metadata": {
    "description": "General chat room",
    "category": "public",
    "created_by": "admin"
  }
}
```

**Response:**
```json
{
  "name": "chat-room-1",
  "subscriber_count": 0,
  "config": {
    "max_subscribers": 1000,
    "require_auth": true,
    "permissions": {
      "read": ["user", "admin"],
      "write": ["user", "admin"],
      "admin": ["admin"]
    },
    "metadata": {
      "description": "General chat room",
      "category": "public",
      "created_by": "admin"
    }
  }
}
```

#### Get Channel Information
```http
GET /realtime/channels/chat-room-1
```

**Response:**
```json
{
  "name": "chat-room-1",
  "subscriber_count": 25,
  "presence": {
    "user123": {
      "status": "online",
      "last_seen": "2025-01-15T10:30:00Z",
      "custom_data": {
        "avatar": "https://example.com/avatar.jpg",
        "display_name": "John Doe"
      }
    },
    "user456": {
      "status": "away",
      "last_seen": "2025-01-15T10:25:00Z"
    }
  }
}
```

#### List All Channels
```http
GET /realtime/channels
```

**Response:**
```json
{
  "channels": [
    {
      "name": "chat-room-1",
      "subscriber_count": 25,
      "presence_count": 20
    },
    {
      "name": "notifications",
      "subscriber_count": 150,
      "presence_count": 145
    }
  ],
  "total": 2
}
```

#### Delete Channel
```http
DELETE /realtime/channels/chat-room-1
```

**Response:**
```json
{
  "message": "channel deleted successfully"
}
```

### 2. WebSocket Connection

#### Connect to Channel
```javascript
// WebSocket connection with authentication
const ws = new WebSocket('ws://localhost:8080/realtime/channels/chat-room-1/ws?token=your_jwt_token');

// Or with Authorization header
const ws = new WebSocket('ws://localhost:8080/realtime/channels/chat-room-1/ws', [], {
  headers: {
    'Authorization': 'Bearer your_jwt_token'
  }
});
```

#### WebSocket Message Format
```javascript
// Outgoing message format
{
  "id": "msg_1642234567890_abc123",
  "type": "broadcast",
  "event": "chat_message",
  "payload": {
    "message": "Hello everyone!",
    "timestamp": "2025-01-15T10:30:00Z"
  },
  "user_id": "user123",
  "timestamp": "2025-01-15T10:30:00Z"
}

// Incoming message format (same structure)
{
  "id": "msg_1642234567891_def456",
  "type": "message",
  "event": "chat_message",
  "payload": {
    "message": "Hello back!",
    "user": "Jane Doe"
  },
  "user_id": "user456",
  "timestamp": "2025-01-15T10:30:15Z"
}
```

### 3. Message Broadcasting

#### Broadcast Message to Channel
```http
POST /realtime/channels/chat-room-1/broadcast
Content-Type: application/json
Authorization: Bearer <access_token>

{
  "type": "message",
  "event": "announcement",
  "payload": {
    "title": "System Maintenance",
    "message": "The system will be down for maintenance at 2 AM UTC",
    "priority": "high",
    "expires_at": "2025-01-16T02:00:00Z"
  }
}
```

**Response:**
```json
{
  "message": "message broadcasted successfully",
  "id": "msg_1642234567892_ghi789"
}
```

### 4. Presence Management

#### Get Channel Presence
```http
GET /realtime/channels/chat-room-1/presence
```

**Response:**
```json
{
  "channel": "chat-room-1",
  "presence": {
    "user123": {
      "status": "online",
      "last_seen": "2025-01-15T10:30:00Z",
      "custom_data": {
        "avatar": "https://example.com/avatar.jpg",
        "display_name": "John Doe",
        "role": "moderator"
      }
    },
    "user456": {
      "status": "away",
      "last_seen": "2025-01-15T10:25:00Z",
      "custom_data": {
        "display_name": "Jane Smith"
      }
    }
  },
  "connected_users": ["user123", "user456", "user789"],
  "total_users": 3
}
```

#### Update User Presence
```http
POST /realtime/channels/chat-room-1/presence
Content-Type: application/json
Authorization: Bearer <access_token>

{
  "state": {
    "status": "busy",
    "custom_message": "In a meeting",
    "available_until": "2025-01-15T11:00:00Z",
    "custom_data": {
      "avatar": "https://example.com/new-avatar.jpg",
      "display_name": "John Doe",
      "role": "moderator"
    }
  }
}
```

**Response:**
```json
{
  "message": "presence updated successfully"
}
```

### 5. Database Change Streaming

#### Subscribe to Database Changes
```http
POST /realtime/channels/chat-room-1/subscribe
Content-Type: application/json
Authorization: Bearer <access_token>

{
  "table": "messages",
  "schema": "public",
  "events": ["INSERT", "UPDATE", "DELETE"],
  "columns": ["id", "content", "user_id", "created_at"],
  "condition": "user_id IS NOT NULL"
}
```

**Response:**
```json
{
  "message": "subscribed to database changes",
  "channel": "chat-room-1",
  "filter": {
    "table": "messages",
    "schema": "public",
    "events": ["INSERT", "UPDATE", "DELETE"],
    "columns": ["id", "content", "user_id", "created_at"],
    "condition": "user_id IS NOT NULL"
  }
}
```

#### Database Change Event Format
```javascript
// WebSocket message received when database changes occur
{
  "id": "msg_1642234567893_jkl012",
  "type": "database_change",
  "event": "INSERT.messages",
  "payload": {
    "change": {
      "id": "change_1642234567893",
      "table": "messages",
      "schema": "public",
      "event": "INSERT",
      "old_record": null,
      "new_record": {
        "id": 123,
        "content": "New message content",
        "user_id": "user123",
        "created_at": "2025-01-15T10:30:00Z"
      },
      "timestamp": "2025-01-15T10:30:00Z"
    }
  },
  "user_id": "system",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### 6. Database Trigger Management

#### Setup Table Trigger
```http
POST /realtime/triggers/messages
```

**Response:**
```json
{
  "message": "trigger setup successfully",
  "table": "messages"
}
```

#### Remove Table Trigger
```http
DELETE /realtime/triggers/messages
```

**Response:**
```json
{
  "message": "trigger removed successfully",
  "table": "messages"
}
```

### 7. Statistics and Monitoring

#### Get Channel Statistics
```http
GET /realtime/channels/chat-room-1/stats
```

**Response:**
```json
{
  "channel": "chat-room-1",
  "subscriber_count": 25,
  "presence_count": 20,
  "connected_users": 25,
  "users": ["user123", "user456", "user789"]
}
```

#### Get System Statistics
```http
GET /realtime/stats
```

**Response:**
```json
{
  "total_channels": 5,
  "total_subscribers": 150,
  "total_presence": 145,
  "channels": [
    {
      "name": "chat-room-1",
      "subscriber_count": 25,
      "presence_count": 20
    },
    {
      "name": "notifications",
      "subscriber_count": 100,
      "presence_count": 95
    }
  ]
}
```

#### Get Database Subscriptions
```http
GET /realtime/subscriptions
```

**Response:**
```json
{
  "subscriptions": [
    {
      "id": "sub_1642234567890",
      "channel_name": "chat-room-1",
      "filter": {
        "table": "messages",
        "schema": "public",
        "events": ["INSERT", "UPDATE", "DELETE"]
      },
      "user_id": "user123",
      "created_at": "2025-01-15T10:00:00Z",
      "last_activity": "2025-01-15T10:30:00Z",
      "message_count": 15
    }
  ],
  "total": 1
}
```

## WebSocket Client Examples

### JavaScript Client

```javascript
class RealtimeClient {
  constructor(channelName, token) {
    this.channelName = channelName;
    this.token = token;
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
  }

  connect() {
    const wsUrl = `ws://localhost:8080/realtime/channels/${this.channelName}/ws?token=${this.token}`;
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log('Connected to channel:', this.channelName);
      this.reconnectAttempts = 0;
      
      // Send initial presence
      this.updatePresence({
        status: 'online',
        joined_at: new Date().toISOString()
      });
    };

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      this.handleMessage(message);
    };

    this.ws.onclose = () => {
      console.log('Disconnected from channel:', this.channelName);
      this.attemptReconnect();
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }

  handleMessage(message) {
    switch (message.type) {
      case 'system':
        this.handleSystemMessage(message);
        break;
      case 'message':
        this.handleChatMessage(message);
        break;
      case 'presence':
        this.handlePresenceUpdate(message);
        break;
      case 'database_change':
        this.handleDatabaseChange(message);
        break;
      case 'pong':
        // Handle ping/pong for connection health
        break;
      default:
        console.log('Unknown message type:', message.type);
    }
  }

  handleSystemMessage(message) {
    if (message.event === 'connected') {
      console.log('Successfully connected to channel');
    } else if (message.event === 'channel_closed') {
      console.log('Channel was closed:', message.payload.reason);
    }
  }

  handleChatMessage(message) {
    console.log('New message:', message.payload);
    // Update UI with new message
  }

  handlePresenceUpdate(message) {
    console.log('Presence update:', message.payload);
    // Update user list UI
  }

  handleDatabaseChange(message) {
    const change = message.payload.change;
    console.log('Database change:', change);
    
    if (change.table === 'messages' && change.event === 'INSERT') {
      // Handle new message from database
      this.handleNewMessageFromDB(change.new_record);
    }
  }

  sendMessage(event, payload) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      const message = {
        type: 'broadcast',
        event: event,
        payload: payload,
        timestamp: new Date().toISOString()
      };
      this.ws.send(JSON.stringify(message));
    }
  }

  updatePresence(state) {
    const message = {
      type: 'presence',
      event: 'update',
      payload: { state: state },
      timestamp: new Date().toISOString()
    };
    this.ws.send(JSON.stringify(message));
  }

  ping() {
    const message = {
      type: 'ping',
      event: 'ping',
      payload: {},
      timestamp: new Date().toISOString()
    };
    this.ws.send(JSON.stringify(message));
  }

  attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.pow(2, this.reconnectAttempts) * 1000; // Exponential backoff
      
      console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
      
      setTimeout(() => {
        this.connect();
      }, delay);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

// Usage
const client = new RealtimeClient('chat-room-1', 'your_jwt_token');
client.connect();

// Send a chat message
client.sendMessage('chat_message', {
  message: 'Hello everyone!',
  user: 'John Doe'
});

// Update presence
client.updatePresence({
  status: 'typing',
  message: 'is typing...'
});
```

### React Hook Example

```javascript
import { useState, useEffect, useRef } from 'react';

export function useRealtime(channelName, token) {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState([]);
  const [presence, setPresence] = useState({});
  const [error, setError] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    if (!channelName || !token) return;

    const connect = () => {
      const wsUrl = `ws://localhost:8080/realtime/channels/${channelName}/ws?token=${token}`;
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        setConnected(true);
        setError(null);
      };

      wsRef.current.onmessage = (event) => {
        const message = JSON.parse(event.data);
        
        if (message.type === 'message') {
          setMessages(prev => [...prev, message]);
        } else if (message.type === 'presence') {
          setPresence(prev => ({
            ...prev,
            [message.payload.user_id]: message.payload.state
          }));
        }
      };

      wsRef.current.onclose = () => {
        setConnected(false);
      };

      wsRef.current.onerror = (error) => {
        setError(error);
      };
    };

    connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [channelName, token]);

  const sendMessage = (event, payload) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const message = {
        type: 'broadcast',
        event: event,
        payload: payload,
        timestamp: new Date().toISOString()
      };
      wsRef.current.send(JSON.stringify(message));
    }
  };

  const updatePresence = (state) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const message = {
        type: 'presence',
        event: 'update',
        payload: { state: state },
        timestamp: new Date().toISOString()
      };
      wsRef.current.send(JSON.stringify(message));
    }
  };

  return {
    connected,
    messages,
    presence,
    error,
    sendMessage,
    updatePresence
  };
}

// Usage in component
function ChatRoom({ channelName, token }) {
  const { connected, messages, presence, sendMessage, updatePresence } = useRealtime(channelName, token);
  const [messageText, setMessageText] = useState('');

  const handleSendMessage = () => {
    if (messageText.trim()) {
      sendMessage('chat_message', {
        message: messageText,
        timestamp: new Date().toISOString()
      });
      setMessageText('');
    }
  };

  useEffect(() => {
    if (connected) {
      updatePresence({
        status: 'online',
        joined_at: new Date().toISOString()
      });
    }
  }, [connected]);

  return (
    <div>
      <div>Status: {connected ? 'Connected' : 'Disconnected'}</div>
      
      <div>
        <h3>Messages</h3>
        {messages.map(msg => (
          <div key={msg.id}>
            <strong>{msg.user_id}:</strong> {msg.payload.message}
          </div>
        ))}
      </div>

      <div>
        <h3>Online Users</h3>
        {Object.entries(presence).map(([userId, state]) => (
          <div key={userId}>
            {userId}: {state.status}
          </div>
        ))}
      </div>

      <div>
        <input
          value={messageText}
          onChange={(e) => setMessageText(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
        />
        <button onClick={handleSendMessage}>Send</button>
      </div>
    </div>
  );
}
```

## Database Integration

### Setting Up Database Triggers

The realtime system can automatically listen for database changes using PostgreSQL triggers:

```sql
-- The system automatically creates this function
CREATE OR REPLACE FUNCTION notify_table_changes()
RETURNS TRIGGER AS $
DECLARE
    notification JSON;
    old_record JSON;
    new_record JSON;
BEGIN
    -- Handle different trigger operations
    IF TG_OP = 'DELETE' THEN
        old_record = row_to_json(OLD);
        new_record = NULL;
    ELSIF TG_OP = 'INSERT' THEN
        old_record = NULL;
        new_record = row_to_json(NEW);
    ELSIF TG_OP = 'UPDATE' THEN
        old_record = row_to_json(OLD);
        new_record = row_to_json(NEW);
    END IF;

    -- Build notification payload
    notification = json_build_object(
        'table', TG_TABLE_NAME,
        'schema', TG_TABLE_SCHEMA,
        'event', TG_OP,
        'old_record', old_record,
        'new_record', new_record,
        'timestamp', extract(epoch from now())
    );

    -- Send notification
    PERFORM pg_notify('table_changes', notification::text);

    -- Return appropriate record
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$ LANGUAGE plpgsql;

-- Example trigger for messages table
CREATE TRIGGER messages_changes_trigger
    AFTER INSERT OR UPDATE OR DELETE ON messages
    FOR EACH ROW
    EXECUTE FUNCTION notify_table_changes();
```

### Database Change Filtering

```javascript
// Subscribe to specific table changes
await fetch('/realtime/channels/chat-room/subscribe', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  },
  body: JSON.stringify({
    table: 'messages',
    schema: 'public',
    events: ['INSERT', 'UPDATE'],  // Only listen for inserts and updates
    columns: ['id', 'content', 'user_id'],  // Only include these columns
    condition: 'user_id IS NOT NULL'  // Custom condition
  })
});
```

## Message Types and Events

### System Messages
- **`connected`**: User successfully connected to channel
- **`channel_closed`**: Channel is being closed
- **`error`**: Error occurred

### User Messages
- **`message`**: Regular chat message
- **`broadcast`**: Broadcasted message to all users
- **`ping`/`pong`**: Connection health check

### Presence Messages
- **`update`**: User presence state updated
- **`join`**: User joined channel
- **`leave`**: User left channel

### Database Change Messages
- **`INSERT.table_name`**: New record inserted
- **`UPDATE.table_name`**: Record updated
- **`DELETE.table_name`**: Record deleted

## Configuration

### Service Configuration

```go
// Channel Manager Configuration
config := ChannelManagerConfig{
    MaxChannels:     1000,           // Maximum number of channels
    DefaultMaxUsers: 100,            // Default max users per channel
    ChannelTTL:      24 * time.Hour, // Channel time-to-live
    CleanupInterval: 5 * time.Minute, // Cleanup interval
    EnableMetrics:   true,           // Enable metrics collection
    EnablePresence:  true,           // Enable presence tracking
    EnableBroadcast: true,           // Enable broadcasting
}

// Database Listener Configuration
dbConfig := DatabaseListenerConfig{
    ReplicationSlot:   "realtime_slot",     // PostgreSQL replication slot
    PublicationName:   "realtime_publication", // PostgreSQL publication
    HeartbeatInterval: 30 * time.Second,    // Heartbeat interval
    MaxReconnectDelay: 30 * time.Second,    // Max reconnection delay
    EnableRLS:         true,                // Enable Row Level Security
    FilterTables:      []string{"messages", "users"}, // Tables to monitor
    ExcludeTables:     []string{"logs"},    // Tables to exclude
}
```

### Environment Variables

```bash
# WebSocket Configuration
REALTIME_MAX_CHANNELS=1000
REALTIME_MAX_USERS_PER_CHANNEL=100
REALTIME_ENABLE_METRICS=true
REALTIME_ENABLE_PRESENCE=true

# Database Integration
REALTIME_ENABLE_DB_STREAMING=true
REALTIME_REPLICATION_SLOT=realtime_slot
REALTIME_PUBLICATION_NAME=realtime_publication
REALTIME_ENABLE_RLS=true

# Connection Management
REALTIME_CONNECTION_TIMEOUT=60s
REALTIME_PING_INTERVAL=30s
REALTIME_CLEANUP_INTERVAL=5m
```

## Security Features

### 🔐 Authentication & Authorization

1. **JWT Authentication**: All WebSocket connections require valid JWT tokens
2. **Channel Permissions**: Fine-grained permissions for read/write/admin access
3. **User Context**: All operations are performed in the authenticated user's context
4. **Token Validation**: Continuous token validation during connection lifetime

```javascript
// Authentication examples
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';

// WebSocket with token in query parameter
const ws = new WebSocket(`ws://localhost:8080/realtime/channels/secure-channel/ws?token=${token}`);

// HTTP API with Authorization header
fetch('/realtime/channels/secure-channel/broadcast', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    type: 'message',
    event: 'secure_message',
    payload: { message: 'This is secure' }
  })
});
```

### 🛡️ Row Level Security (RLS)

1. **Database-Level Security**: Enforces PostgreSQL RLS policies
2. **User Context Filtering**: Database changes are filtered based on user permissions
3. **Automatic Policy Application**: RLS policies are automatically applied to change streams

```sql
-- Example RLS policy for messages table
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY messages_select_policy ON messages
    FOR SELECT
    USING (user_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY messages_insert_policy ON messages
    FOR INSERT
    WITH CHECK (user_id = current_setting('app.current_user_id')::uuid);
```

### 🔒 Connection Security

1. **Origin Validation**: WebSocket origin checking (configurable)
2. **Rate Limiting**: Connection and message rate limiting
3. **Automatic Cleanup**: Stale connection detection and cleanup
4. **Connection Limits**: Per-user and per-channel connection limits

## Performance Optimization

### Connection Management

```go
// Connection pool configuration
connManager := NewConnectionManager()

// Metrics tracking
metrics := connManager.GetMetrics()
fmt.Printf("Active connections: %d\n", metrics.ActiveConnections)
fmt.Printf("Connections per user: %v\n", metrics.ConnectionsPerUser)
fmt.Printf("Channel connections: %v\n", metrics.ChannelConnections)
```

### Channel Optimization

```go
// Optimized channel configuration
config := interfaces.ChannelConfig{
    MaxSubscribers: 1000,        // Limit subscribers per channel
    RequireAuth:    true,        // Reduce unauthorized connections
    Permissions: map[string]interface{}{
        "max_message_size": 1024,  // Limit message size
        "rate_limit": 10,          // Messages per second per user
    },
}
```

### Database Performance

```sql
-- Optimize database triggers for performance
CREATE INDEX CONCURRENTLY idx_messages_user_id_created_at 
ON messages(user_id, created_at DESC);

-- Partition large tables for better trigger performance
CREATE TABLE messages_2025_01 PARTITION OF messages
FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
```

## Error Handling

### Common Error Responses

#### WebSocket Connection Errors
```json
{
  "error": "authentication failed",
  "code": "AUTH_FAILED",
  "details": "Invalid or expired token"
}
```

#### Channel Errors
```json
{
  "error": "channel chat-room-1 not found",
  "code": "CHANNEL_NOT_FOUND"
}
```

#### Permission Errors
```json
{
  "error": "insufficient permissions",
  "code": "PERMISSION_DENIED",
  "required_permission": "write"
}
```

#### Rate Limit Errors
```json
{
  "error": "rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "retry_after": 30
}
```

#### Database Errors
```json
{
  "error": "failed to subscribe to database changes",
  "code": "DB_SUBSCRIPTION_FAILED",
  "details": "Table 'nonexistent' does not exist"
}
```

### Client Error Handling

```javascript
class RealtimeClient {
  handleError(error) {
    switch (error.code) {
      case 'AUTH_FAILED':
        // Refresh token and reconnect
        this.refreshTokenAndReconnect();
        break;
      case 'RATE_LIMIT_EXCEEDED':
        // Wait and retry
        setTimeout(() => this.connect(), error.retry_after * 1000);
        break;
      case 'CHANNEL_NOT_FOUND':
        // Create channel or redirect user
        this.handleChannelNotFound();
        break;
      default:
        console.error('Unhandled error:', error);
    }
  }
}
```

## Monitoring & Metrics

### System Metrics

```bash
# Get real-time system statistics
curl -X GET http://localhost:8080/realtime/stats \
  -H "Authorization: Bearer <token>"

# Response includes:
# - Total channels and subscribers
# - Per-channel statistics
# - Connection metrics
# - Database subscription counts
```

### Connection Metrics

```javascript
// Client-side connection monitoring
class ConnectionMonitor {
  constructor(client) {
    this.client = client;
    this.metrics = {
      connectTime: null,
      messagesSent: 0,
      messagesReceived: 0,
      reconnectCount: 0,
      lastPing: null
    };
  }

  startMonitoring() {
    // Track connection time
    this.metrics.connectTime = Date.now();
    
    // Ping every 30 seconds
    this.pingInterval = setInterval(() => {
      this.client.ping();
      this.metrics.lastPing = Date.now();
    }, 30000);
  }

  onMessageSent() {
    this.metrics.messagesSent++;
  }

  onMessageReceived() {
    this.metrics.messagesReceived++;
  }

  getMetrics() {
    return {
      ...this.metrics,
      uptime: Date.now() - this.metrics.connectTime,
      avgLatency: this.calculateAverageLatency()
    };
  }
}
```

## Testing Examples

### Unit Testing

```bash
# Run realtime service tests
go test ./internal/realtime -v

# Run integration tests with database
go test ./internal/realtime -tags=integration -v

# Test specific functionality
go test ./internal/realtime -run TestChannel_BasicOperations -v
```

### WebSocket Connection Testing

The issue you encountered was due to the realtime service being initialized with a `nil` auth service. This has been fixed by creating an auth service adapter that properly implements the required interface.

**Fixed Issues:**
1. **Nil Pointer Dereference**: The auth service was `nil` in the realtime service
2. **Interface Mismatch**: Created `auth.ServiceAdapter` to bridge interface differences
3. **Proper Token Validation**: WebSocket connections now properly validate JWT tokens

**Test WebSocket Connection:**
```bash
# Start the server
./server.exe

# Open test_websocket.html in your browser
# Or use a WebSocket client to connect to:
ws://localhost:8080/realtime/channels/test-channel/ws?token=YOUR_JWT_TOKEN
```

### Load Testing

```javascript
// WebSocket load testing script
const WebSocket = require('ws');

async function loadTest() {
  const connections = [];
  const numConnections = 100;
  const channelName = 'load-test-channel';
  
  // Create multiple connections
  for (let i = 0; i < numConnections; i++) {
    const ws = new WebSocket(`ws://localhost:8080/realtime/channels/${channelName}/ws?token=test-token`);
    
    ws.on('open', () => {
      console.log(`Connection ${i} opened`);
      
      // Send periodic messages
      setInterval(() => {
        ws.send(JSON.stringify({
          type: 'broadcast',
          event: 'load_test',
          payload: { message: `Message from connection ${i}` }
        }));
      }, 1000);
    });
    
    connections.push(ws);
  }
  
  // Monitor for 60 seconds
  setTimeout(() => {
    connections.forEach(ws => ws.close());
    console.log('Load test completed');
  }, 60000);
}

loadTest();
```

### Integration Testing

Use the provided test script to test all API endpoints:

```bash
# Make the test script executable
chmod +x test_realtime_api.sh

# Run the complete API test suite
./test_realtime_api.sh
```

**Manual API Testing:**

```bash
# Test channel creation and messaging
curl -X POST http://localhost:8080/realtime/channels \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"name": "test-channel", "max_subscribers": 100}'

# Test database change subscription
curl -X POST http://localhost:8080/realtime/channels/test-channel/subscribe \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"table": "test_table", "events": ["INSERT", "UPDATE"]}'

# Test message broadcasting
curl -X POST http://localhost:8080/realtime/channels/test-channel/broadcast \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"type": "message", "event": "test", "payload": {"data": "test"}}'
```

**WebSocket Testing with Browser:**

1. Start your server: `./server.exe`
2. Open `test_websocket.html` in your browser
3. The page will automatically connect to the WebSocket endpoint
4. Send test messages and observe real-time communication

## Best Practices

### 🚀 Performance Best Practices

1. **Connection Pooling**: Reuse connections when possible
2. **Message Batching**: Batch multiple small messages
3. **Presence Throttling**: Limit presence update frequency
4. **Channel Cleanup**: Regularly clean up unused channels
5. **Database Indexing**: Optimize database queries for change detection

### 🔧 Development Best Practices

1. **Error Handling**: Implement comprehensive error handling
2. **Reconnection Logic**: Use exponential backoff for reconnections
3. **Message Validation**: Validate all incoming messages
4. **Rate Limiting**: Implement client-side rate limiting
5. **Monitoring**: Add comprehensive logging and metrics

### 🛡️ Security Best Practices

1. **Token Validation**: Continuously validate JWT tokens
2. **Origin Checking**: Validate WebSocket origins
3. **Input Sanitization**: Sanitize all user inputs
4. **Permission Checks**: Implement fine-grained permissions
5. **RLS Enforcement**: Use database-level security policies

This comprehensive realtime documentation covers all aspects of the GoForward realtime system, providing both HTTP API endpoints and WebSocket functionality for complete real-time communication capabilities.