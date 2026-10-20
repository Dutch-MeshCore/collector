import Aedes from 'aedes';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { Duplex } from 'stream';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { getAirportInfo } from 'airport-utils';
import { RateLimiter } from './rate-limiter';
import { getClientIP } from './ip-utils';
import { AbuseDetector } from './abuse-detector';
import { loadMqttConfig, loadAbuseConfig, loadSubscriberConfig } from './config';
import { logDebug, logInfo, logWarn } from './logger';

// Last-resort crash visibility. Without these, a throw from a timer or an unhandled promise
// rejection kills the process with no usable stack trace in the container logs. We log the
// full stack and still exit(1): the process state is unknown after an uncaught exception, so
// continuing would be unsafe. The container restart policy brings the broker back.
process.on('uncaughtException', (err, origin) => {
  console.error(`[FATAL] Uncaught exception (${origin}):`, err instanceof Error ? err.stack || err : err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled promise rejection:', reason instanceof Error ? reason.stack || reason : reason);
  process.exit(1);
});

// Load and validate configuration
const mqttConfig = loadMqttConfig();
const abuseConfig = loadAbuseConfig();
const subscriberConfig = loadSubscriberConfig();

const WS_PORT = mqttConfig.wsPort;
const HOST = mqttConfig.host;
const EXPECTED_AUDIENCE = mqttConfig.expectedAudience;
// Where a plain (non-WebSocket) browser request to the broker is redirected. This
// broker only speaks MQTT-over-WS, so a human hitting the URL is sent to the
// front-end. Configurable; defaults to the DMC observers site.
const HTTP_REDIRECT_URL = process.env.HTTP_REDIRECT_URL || 'https://observers.dutchmeshcore.nl/';
// Non-IATA stream-region labels (e.g. wardriver, hunter) accepted in the topic
// region slot alongside real IATA codes and "test". Kept lowercase.
const EXTRA_PUBLISH_REGIONS = mqttConfig.extraPublishRegions;

// Helper function to validate IATA airport codes
function isValidIATACode(code: string): boolean {
  try {
    getAirportInfo(code);
    return true;
  } catch {
    return false;
  }
}

// Client types
enum ClientType {
  SUBSCRIBER = 'subscriber',
  PUBLISHER = 'publisher'
}

// Subscriber roles
enum SubscriberRole {
  ADMIN = 1,           // Full access + can delete retained messages
  FULL_ACCESS = 2,     // Full access, no hidden data
  LIMITED = 3          // All access but with hidden/sensitive data filtered
}

// Load subscriber users from environment variables
// Format: SUBSCRIBER_1=username:password:role:maxConnections, SUBSCRIBER_2=username:password:role:maxConnections, etc.
// Role: 1=admin (full+delete), 2=full_access (no hidden data), 3=limited (filtered data)
// maxConnections: number for override, D or omit to use default
const subscriberUsers = new Map<string, string>();
const subscriberRoles = new Map<string, SubscriberRole>();
const subscriberMaxConnections = new Map<string, number>();

// Track active connections per subscriber username
const subscriberActiveConnections = new Map<string, Set<string>>();

// Collector stats config
const COLLECTOR_NAME = process.env.COLLECTOR_NAME || 'collector';
const STATS_TOPIC_PREFIX = process.env.STATS_TOPIC_PREFIX || 'stats';
const STATS_INTERVAL_MS = parseInt(process.env.STATS_INTERVAL_MS || '30000', 10);
const STATS_RETAIN = (process.env.STATS_RETAIN || 'true').toLowerCase() === 'true';
const STATS_INCLUDE_TOKEN_CLIENT_DETAILS =
  (process.env.STATS_INCLUDE_TOKEN_CLIENT_DETAILS || 'false').toLowerCase() === 'true';

// Track detailed connected subscriber clients for stats
type ConnectedSubscriber = {
  clientId: string;
  username: string;
  role: SubscriberRole;
  roleName: string;
  connectedAt: number;
  ip?: string;
};

// Track token-authenticated publisher clients for stats
type ConnectedTokenClient = {
  clientId: string;
  publicKeyShort: string;
  audience?: string;
  connectedAt: number;
  ip?: string;
};

const connectedSubscribers = new Map<string, ConnectedSubscriber>();
const connectedTokenClients = new Map<string, ConnectedTokenClient>();

// Message counters for collector stats
let messagesReceivedTotal = 0;
let messagesReceivedBytesTotal = 0;
let meshcoreMessagesReceivedTotal = 0;
let messagesReceivedSinceLastStats = 0;
let messagesReceivedBytesSinceLastStats = 0;
let lastStatsPublishedAt = Date.now();

function getSubscriberRoleName(role: SubscriberRole): string {
  if (role === SubscriberRole.ADMIN) return 'admin';
  if (role === SubscriberRole.FULL_ACCESS) return 'full_access';
  return 'limited';
}

function cleanTopicPart(value: string): string {
  return value.replace(/^\/+|\/+$/g, '');
}

function getStatsTopic(): string {
  const prefix = cleanTopicPart(STATS_TOPIC_PREFIX);
  const collectorName = cleanTopicPart(COLLECTOR_NAME);
  return `${prefix}/${collectorName}/connected_clients`;
}

function buildCollectorStatsPayload() {
  const now = Date.now();

  const subscribers = Array.from(connectedSubscribers.values()).map((subscriber) => ({
    username: subscriber.username,
    client_id: subscriber.clientId,
    role: subscriber.roleName,
    ip: subscriber.ip,
    connected_at: new Date(subscriber.connectedAt).toISOString(),
    connected_seconds: Math.floor((now - subscriber.connectedAt) / 1000),
  }));

  const tokenClients = Array.from(connectedTokenClients.values()).map((tokenClient) => ({
    client_id: tokenClient.clientId,
    public_key_short: tokenClient.publicKeyShort,
    ip: tokenClient.ip,
    audience: tokenClient.audience,
    connected_at: new Date(tokenClient.connectedAt).toISOString(),
    connected_seconds: Math.floor((now - tokenClient.connectedAt) / 1000),
  }));

  const elapsedSeconds = Math.max((now - lastStatsPublishedAt) / 1000, 0.001);
  const messagesPerSecond = messagesReceivedSinceLastStats / elapsedSeconds;

  const payload: any = {
    collector: COLLECTOR_NAME,
    timestamp: new Date(now).toISOString(),
    connected_subscriber_count: subscribers.length,
    connected_subscribers: subscribers,
    connected_token_client_count: tokenClients.length,

    messages_received_total: messagesReceivedTotal,
    messages_received_bytes_total: messagesReceivedBytesTotal,
    meshcore_messages_received_total: meshcoreMessagesReceivedTotal,
    messages_received_since_last_stats: messagesReceivedSinceLastStats,
    messages_received_bytes_since_last_stats: messagesReceivedBytesSinceLastStats,
    messages_received_per_second: Math.round(messagesPerSecond * 100) / 100,
  };

  if (STATS_INCLUDE_TOKEN_CLIENT_DETAILS) {
    payload.connected_token_clients = tokenClients;
  } else {
    payload.excluded = 'token authenticated publisher clients are not included';
  }

  messagesReceivedSinceLastStats = 0;
  messagesReceivedBytesSinceLastStats = 0;
  lastStatsPublishedAt = now;

  return payload;
}

function publishCollectorStats(): void {
  // Runs from a timer: a failed tick must be logged, never allowed to kill the process.
  try {
    const topic = getStatsTopic();
    const payload = Buffer.from(JSON.stringify(buildCollectorStatsPayload()));

    aedes.publish(
      {
        cmd: 'publish',
        topic,
        payload,
        qos: 0,
        retain: STATS_RETAIN,
        dup: false,
      },
      (err) => {
        if (err) {
          console.error(`[STATS] Failed to publish stats to ${topic}:`, err);
        }
      }
    );
  } catch (error) {
    console.error('[STATS] Failed to build/publish collector stats:', error);
  }
}

let subscriberIndex = 1;
while (true) {
  const subscriberEnvVar = process.env[`SUBSCRIBER_${subscriberIndex}`];
  if (!subscriberEnvVar) {
    break;
  }
  
  const parts = subscriberEnvVar.split(':').map(s => s.trim());
  const username = parts[0];
  const password = parts[1];
  const roleStr = parts[2];
  const maxConnStr = parts[3];
  
  if (username && password) {
    subscriberUsers.set(username, password);
    
    // Parse and store role (default to LIMITED if not specified or invalid)
    let role = SubscriberRole.LIMITED;
    if (roleStr) {
      const roleNum = parseInt(roleStr);
      if (roleNum === 1 || roleNum === 2 || roleNum === 3) {
        role = roleNum as SubscriberRole;
      }
    }
    subscriberRoles.set(username, role);
    
    // Parse and store max connections (D or empty = default, number = override)
    let maxConn = subscriberConfig.defaultMaxConnections;
    if (maxConnStr && maxConnStr.toUpperCase() !== 'D') {
      const parsedMax = parseInt(maxConnStr);
      if (!isNaN(parsedMax) && parsedMax > 0) {
        maxConn = parsedMax;
      }
    }
    subscriberMaxConnections.set(username, maxConn);
    
    // Initialize active connections set for this user
    subscriberActiveConnections.set(username, new Set());
    
    const roleNames = {
      [SubscriberRole.ADMIN]: 'admin',
      [SubscriberRole.FULL_ACCESS]: 'full_access', 
      [SubscriberRole.LIMITED]: 'limited'
    };
    logInfo(`[CONFIG] Loaded subscriber user: ${username} (role: ${roleNames[role]}, maxConnections: ${maxConn})`);
  } else {
    logWarn(`[CONFIG] Invalid format for SUBSCRIBER_${subscriberIndex}: ${subscriberEnvVar}`);
  }
  
  subscriberIndex++;
}

if (subscriberUsers.size === 0) {
  logInfo('[CONFIG] No subscriber users configured');
} else {
  logInfo(`[CONFIG] Default max connections per subscriber: ${subscriberConfig.defaultMaxConnections}`);
}

// Create Aedes MQTT broker
const aedes = new Aedes();

// Rate limiting for failed connections
const rateLimiter = new RateLimiter(60000, 10, 300000);

// Abuse detection
const abuseDetector = new AbuseDetector(abuseConfig);

// Helper to get client identifier for logging
function getClientLogPrefix(client: any): string {
  if (!client) return '[UNKNOWN]';
  
  const clientType = client.clientType;
  if (clientType === ClientType.PUBLISHER && client.publicKey) {
    return `[O:${client.publicKey.substring(0, 8)}]`;
  } else if (clientType === ClientType.SUBSCRIBER && client.username) {
    return `[S:${client.username}]`;
  }
  return `[C:${client.id}]`;
}

// Authentication handler
aedes.authenticate = async (client, username, password, callback) => {
  const logPrefix = `[C:${client.id}]`;
  logInfo(`${logPrefix} [AUTH] Authentication attempt - Username: ${username}`);

  try {
    const usernameStr = username?.toString() || '';
    const passwordStr = password?.toString() || '';

    // Check if this is a subscriber login
    if (subscriberUsers.has(usernameStr)) {
      const expectedPassword = subscriberUsers.get(usernameStr);
      if (passwordStr === expectedPassword) {
        // Check connection limit before allowing
        const maxConn = subscriberMaxConnections.get(usernameStr) || subscriberConfig.defaultMaxConnections;
        const activeConns = subscriberActiveConnections.get(usernameStr) || new Set();
        
        if (activeConns.size >= maxConn) {
          logInfo(`${logPrefix} [AUTH] ✗ Subscriber connection limit exceeded (${usernameStr}, ${activeConns.size}/${maxConn})`);
          callback(null, false);
          return;
        }
        
        // Track this connection
        activeConns.add(client.id);
        subscriberActiveConnections.set(usernameStr, activeConns);
        
        const role = subscriberRoles.get(usernameStr) || SubscriberRole.LIMITED;
        logInfo(`${logPrefix} [AUTH] ✓ Subscriber authenticated (${usernameStr}, role: ${role}, connections: ${activeConns.size}/${maxConn})`);
        (client as any).clientType = ClientType.SUBSCRIBER;
        (client as any).username = usernameStr;
        (client as any).role = role;

        connectedSubscribers.set(client.id, {
          clientId: client.id,
          username: usernameStr,
          role,
          roleName: getSubscriberRoleName(role),
          connectedAt: Date.now(),
          ip: (client as any).conn?.clientIP,
        });
        
        // Mark stream as authenticated
        const stream = (client as any).conn;
        if (stream && stream.clientIP) {
          stream.authenticated = true;
        }
        
        callback(null, true);
      } else {
        logInfo(`${logPrefix} [AUTH] ✗ Subscriber authentication failed - Invalid password`);
        callback(null, false);
      }
      return;
    }

    // Otherwise, check for JWT-based publisher authentication
    // Username format: v1_{UPPERCASE_PUBLIC_KEY}
    if (!usernameStr.startsWith('v1_')) {
      logInfo(`${logPrefix} [AUTH] ✗ Invalid username format: ${usernameStr}`);
      callback(null, false);
      return;
    }

    const publicKey = usernameStr.substring(3).toUpperCase().trim();
    
    // Validate public key format (should be 64 hex characters)
    if (!/^[0-9A-F]{64}$/i.test(publicKey)) {
      logInfo(`${logPrefix} [AUTH] ✗ Invalid public key format: ${publicKey}`);
      logInfo(`${logPrefix} [AUTH] Public key length: ${publicKey.length}, hex dump: ${Buffer.from(publicKey).toString('hex')}`);
      callback(null, false);
      return;
    }

    if (!passwordStr || passwordStr.length === 0) {
      logInfo(`${logPrefix} [AUTH] ✗ No password provided`);
      callback(null, false);
      return;
    }

    // Verify the auth token using meshcore-decoder
    const tokenPayload = await verifyAuthToken(passwordStr, publicKey);
    logDebug(`${logPrefix} [AUTH] Token input: "${passwordStr}"`);

    
    if (!tokenPayload) {
      logInfo(`${logPrefix} [AUTH] ✗ Invalid token signature`);
      logDebug(`${logPrefix} [AUTH] Token input: "${passwordStr}"`);      
      logDebug(`${logPrefix} [AUTH] Public key: ${publicKey}`);
      logDebug(`${logPrefix} [AUTH] Token hex: ${Buffer.from(passwordStr).toString('hex')}`);
      callback(null, false);
      return;
    }
    
    // Validate audience claim if configured
    if (EXPECTED_AUDIENCE && tokenPayload.aud !== EXPECTED_AUDIENCE) {
      logInfo(`${logPrefix} [AUTH] ✗ Invalid audience: ${tokenPayload.aud} (expected: ${EXPECTED_AUDIENCE})`);
      callback(null, false);
      return;
    }
    
    const shortKey = publicKey.substring(0, 8);
    logInfo(`[O:${shortKey}] [AUTH] ✓ Publisher authenticated${tokenPayload.aud ? ` [aud: ${tokenPayload.aud}]` : ''}`);
    // Store the public key and client type with the client for later use
    (client as any).publicKey = publicKey;
    (client as any).tokenPayload = tokenPayload;
    (client as any).clientType = ClientType.PUBLISHER;

    connectedTokenClients.set(client.id, {
      clientId: client.id,
      publicKeyShort: shortKey,
      audience: tokenPayload.aud,
      connectedAt: Date.now(),
      ip: (client as any).conn?.clientIP,
    });
    
    // Mark stream as authenticated
    const stream = (client as any).conn;
    if (stream && stream.clientIP) {
      stream.authenticated = true;
    }
    
    // Initialize abuse detection tracking
    const clientIP = stream?.clientIP;
    abuseDetector.initializeClient(publicKey, `v1_${publicKey}`, clientIP);
    
    callback(null, true);
  } catch (error) {
    console.error(`${logPrefix} [AUTH] Error during authentication:`, error);
    callback(null, false);
  }
};

// Authorization handler (control topic access)
aedes.authorizePublish = (client, packet, callback) => {
  if (!client) {
    callback(new Error('No client'));
    return;
  }
  
  const logPrefix = getClientLogPrefix(client);
  const clientType = (client as any).clientType;
  
  // Important: Strip retain flag from /status messages to prevent stale data on ingestor restart
  // LWT (offline) messages are also STATUS messages and should NOT be retained
  if (packet.topic.endsWith('/status') && packet.retain) {
    logInfo(`${logPrefix} [AUTHZ] Stripping retain flag from STATUS message -> ${packet.topic}`);
    packet.retain = false;
  }
  
  // Subscriber clients cannot publish (subscribe-only)
  if (clientType === ClientType.SUBSCRIBER) {
    const role = (client as any).role || SubscriberRole.LIMITED;
    
    // Admin subscribers (role 1) can publish empty retained messages to delete them
    if (role === SubscriberRole.ADMIN && packet.retain && packet.payload.length === 0) {
      logInfo(`${logPrefix} [AUTHZ] ✓ Admin delete authorized -> ${packet.topic}`);
      callback(null);
      return;
    }
    
    // Admin subscribers (role 1) can publish to serial/commands topics for remote serial access
    // Topic format: meshcore/{IATA}/{PUBLIC_KEY}/serial/commands
    if (role === SubscriberRole.ADMIN && packet.topic.endsWith('/serial/commands')) {
      const parts = packet.topic.split('/');
      // Validate: meshcore / IATA / PUBLIC_KEY / serial / commands (5 parts)
      if (parts.length === 5 && parts[0] === 'meshcore' && parts[3] === 'serial') {
        const iata = parts[1];
        const publicKey = parts[2];
        // Basic format validation (real validation happens at meshcoretomqtt via JWT)
        const isValidIata = /^[A-Z]{3}$/i.test(iata) || iata.toLowerCase() === 'test';
        const isValidPubKey = /^[0-9A-Fa-f]{64}$/.test(publicKey);
        if (isValidIata && isValidPubKey) {
          logInfo(`${logPrefix} [AUTHZ] ✓ Admin serial command authorized -> ${packet.topic}`);
          callback(null);
          return;
        }
      }
      logInfo(`${logPrefix} [AUTHZ] ✗ Serial command denied (invalid topic format) -> ${packet.topic}`);
      callback(new Error('Invalid serial/commands topic format'));
      return;
    }
    
    logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied (subscriber) -> ${packet.topic}`);
    callback(new Error('Subscriber clients are subscribe-only'));
    return;
  }
  
  // Publisher clients can only publish to meshcore/* topics
  if (clientType === ClientType.PUBLISHER) {
    if (!packet.topic.startsWith('meshcore/')) {
      logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (not meshcore/*)`);
      callback(new Error('Publishers can only publish to meshcore/* topics'));
      return;
    }

    // Validate topic format
    // Required format: meshcore/{IATA}/{PUBLIC_KEY}/subtopic
    // Examples:
    //   meshcore/SEA/ABCD1234.../packets
    //   meshcore/SEA/ABCD1234.../status
    //   meshcore/SEA/ABCD1234.../internal (ADMIN only)
    const topicParts = packet.topic.split('/').map(part => part.trim());
    if (topicParts.length < 4) {
      logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (must be meshcore/IATA/PUBKEY/subtopic format)`);
      callback(new Error('Topic must be meshcore/IATA/PUBKEY/subtopic format (4 parts required)'));
      return;
    }
    
    const locationCode = topicParts[1].trim();
    const iataRegex = /^[A-Z]{3}$/;
    
    // Reject XXX explicitly (default placeholder value)
    if (locationCode === 'XXX') {
      logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (XXX not valid, configure actual IATA)`);
      logInfo(`${logPrefix} [DISCONNECT] Closing client - Invalid location code: XXX`);
      logInfo(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      callback(new Error('XXX is a placeholder - please configure your actual IATA location code'));
      client.close();
      return;
    }
    
    // Check if this is the special "test" region and normalize it to lowercase
    const isTestRegion = locationCode.toLowerCase() === 'test';
    // Non-IATA stream-region labels (wardriver/hunter) are valid publish regions
    // too: they carry sensitive purpose-collected streams that must stay separable
    // from regional observer traffic, so they skip IATA validation but keep every
    // other check (pubkey match, normalization). Kept lowercase.
    const isStreamRegion = !isTestRegion && EXTRA_PUBLISH_REGIONS.has(locationCode.toLowerCase());

    if (isTestRegion || isStreamRegion) {
      logInfo(`${logPrefix} [AUTHZ] ✓ Using ${isTestRegion ? 'test' : 'stream'} region -> ${packet.topic}`);
      // Continue to validation, don't return here
    } else {
      // First check format (must be 3 uppercase letters, no normalization)
      if (!iataRegex.test(locationCode)) {
        logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid format)`);
        logInfo(`${logPrefix} [DISCONNECT] Closing client - Invalid location format`);
        logInfo(`${logPrefix} [DISCONNECT] Location code: "${locationCode}" (length: ${locationCode.length})`);
        logInfo(`${logPrefix} [DISCONNECT] Location hex: ${Buffer.from(locationCode).toString('hex')}`);
        logInfo(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
        callback(new Error('Location must be exactly 3 uppercase letters (e.g., SEA, PDX, BOS) or "test"'));
        client.close();
        return;
      }
      
      // Then check if it's a valid IATA code
      if (!isValidIATACode(locationCode)) {
        logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid IATA)`);
        logInfo(`${logPrefix} [DISCONNECT] Closing client - Invalid IATA code`);
        logInfo(`${logPrefix} [DISCONNECT] Location code: "${locationCode}"`);
        logInfo(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
        callback(new Error('Location must be a valid IATA international airport code or "test"'));
        client.close();
        return;
      }
    }
    
    // Validate public key in topic (required - topicParts[2])
    const topicPublicKey = topicParts[2].trim().toUpperCase();
    
    // Validate it looks like a public key (64 hex chars)
    if (!/^[0-9A-F]{64}$/i.test(topicPublicKey)) {
      logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid pubkey format)`);
      logInfo(`${logPrefix} [DISCONNECT] Closing client - Invalid public key format in topic`);
      logInfo(`${logPrefix} [DISCONNECT] Topic pubkey: "${topicPublicKey}" (length: ${topicPublicKey.length})`);
      logInfo(`${logPrefix} [DISCONNECT] Topic pubkey hex: ${Buffer.from(topicPublicKey).toString('hex')}`);
      logInfo(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      callback(new Error('Public key in topic must be 64 hex characters'));
      client.close();
      return;
    }
    
    // Validate topic public key matches authenticated client
    const clientPublicKey = (client as any).publicKey.toUpperCase();
    if (topicPublicKey !== clientPublicKey) {
      logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (pubkey mismatch)`);
      logInfo(`${logPrefix} [DISCONNECT] Closing client - Public key mismatch`);
      logInfo(`${logPrefix} [DISCONNECT] Topic pubkey:  "${topicPublicKey}"`);
      logInfo(`${logPrefix} [DISCONNECT] Client pubkey: "${clientPublicKey}"`);
      logInfo(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      callback(new Error('Public key in topic must match authenticated public key'));
      client.close();
      return;
    }

    // Normalize the topic to UPPERCASE for IATA codes and public key component
    // This prevents duplicate topics with different casing (e.g., 7553b337... vs 7553B337...)
    // For the test region, always normalize to lowercase "test"
    const normalizedLocation = isTestRegion
      ? 'test'
      : isStreamRegion
        ? locationCode.toLowerCase()
        : locationCode.toUpperCase();
    const normalizedTopic = `meshcore/${normalizedLocation}/${clientPublicKey}/${topicParts.slice(3).join('/')}`;
    
    // Update the packet topic to the normalized version
    if (packet.topic !== normalizedTopic) {
      logInfo(`${logPrefix} [AUTHZ] Normalized topic: ${packet.topic} -> ${normalizedTopic}`);
      packet.topic = normalizedTopic;
    }

    // Special handling for serial/responses - payload is a JWT string, not JSON
    // Topic format: meshcore/{IATA}/{PUBLIC_KEY}/serial/responses
    const subtopic = topicParts.slice(3).join('/');
    if (subtopic === 'serial/responses') {
      const payload = packet.payload.toString('utf-8');
      // Validate it looks like a JWT (3 base64url parts separated by dots)
      const jwtParts = payload.split('.');
      if (jwtParts.length !== 3) {
        logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JWT format)`);
        callback(new Error('serial/responses payload must be a valid JWT'));
        return;
      }
      // Basic JWT format check - each part should be base64url encoded
      const base64urlRegex = /^[A-Za-z0-9_-]+$/;
      if (!jwtParts.every(part => base64urlRegex.test(part))) {
        logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JWT encoding)`);
        callback(new Error('serial/responses payload must be a valid JWT'));
        return;
      }
      logDebug(`${logPrefix} [AUTHZ] ✓ Publish authorized (serial response) -> ${packet.topic}`);
      callback(null);
      return;
    }

    // Validate that the message contains origin_id matching the authenticated public key
    try {
      const payload = packet.payload.toString('utf-8');
      const message = JSON.parse(payload);
      
      if (!message.origin_id) {
        logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (missing origin_id)`);
        callback(new Error('Message must contain origin_id field'));
        return;
      }
      
      // Normalize both to uppercase for comparison
      const messageOriginId = message.origin_id.toUpperCase();
      const normalizedClientKey = clientPublicKey.toUpperCase();
      
      if (messageOriginId !== normalizedClientKey) {
        logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (origin_id mismatch)`);
        callback(new Error('origin_id must match authenticated public key'));
        return;
      }
      
      // Track with abuse detector (no enforcement, just tracking)
      // Use normalizedLocation to ensure consistent tracking regardless of case
      
      // Check IATA changes
      const publicKey = (client as any).publicKey;
      const trustState = abuseDetector.getClientStats(publicKey);
      if (trustState) {
        abuseDetector.checkIataChange(trustState, normalizedLocation);
        
        // Record packet
        abuseDetector.recordPacket(client, packet);
      }
      
      logDebug(`${logPrefix} [AUTHZ] ✓ Publish authorized -> ${packet.topic}`);
      
      // Publish JWT payload to /internal topic (ADMIN-only, contains PII)
      const tokenPayload = (client as any).tokenPayload;
      if (tokenPayload) {
        // Use normalizedLocation to ensure consistent internal topic naming
        const internalTopic = `meshcore/${normalizedLocation}/${clientPublicKey}/internal`;
        
        // Get trust state for internal message
        const trustState = abuseDetector.getClientStats(clientPublicKey);
        let trustMetrics: any = null;
        
        if (trustState) {
          const clockQuality = trustState.clockTracking.erraticJumps.length === 0 ? 'stable' :
                             trustState.clockTracking.erraticJumps.length < 3 ? 'syncing' : 'erratic';
          
          trustMetrics = {
            status: trustState.status,
            enforcement_enabled: abuseConfig.enforcementEnabled,
            totalPacketsReceived: trustState.totalPacketsReceived,
            totalPacketsSilenced: trustState.totalPacketsSilenced,
            duplicateCount: trustState.duplicateCount,
            anomalyCount: trustState.anomalyCount,
            anomalies: trustState.anomalies.slice(0, 20).map(a => ({
              type: a.type,
              details: a.details,
              timestamp: a.timestamp,
            })),
            peakRateObserved: Math.round(trustState.peakRateObserved * 100) / 100,
            tokenBucket: {
              tokens: Math.round(trustState.tokenBucket.tokens * 10) / 10,
              capacity: trustState.tokenBucket.capacity,
            },
            iataTracking: {
              currentIata: trustState.currentIata,
              iataChangeCount24h: trustState.iataChangeCount24h,
              iataHistory: trustState.iataHistory.map(h => h.iata),
            },
            clockTracking: {
              estimatedOffset: trustState.clockTracking.estimatedOffset ? 
                Math.round(trustState.clockTracking.estimatedOffset / 1000) : undefined,
              erraticJumpCount: trustState.clockTracking.erraticJumps.length,
              lastDeviceTimestamp: trustState.clockTracking.lastDeviceTimestamp,
              clockQuality,
            },
            recentIPs: trustState.recentIPs.slice(0, 10).map(ip => ({
              ip: ip.ip,
              connectionCount: ip.connectionCount,
              lastSeen: ip.lastSeen,
            })),
          };
        }
        
        const internalMessage = {
          origin_id: clientPublicKey,
          timestamp: Date.now(),
          jwt_payload: tokenPayload,
          trust_state: trustMetrics,
        };
        
        // Publish to internal topic (retained so admins can see it later)
        aedes.publish({
          cmd: 'publish',
          topic: internalTopic,
          payload: Buffer.from(JSON.stringify(internalMessage)),
          qos: 0,
          dup: false,
          retain: true
        }, (err) => {
          if (err) {
            console.error(`${logPrefix} [INTERNAL] Failed to publish JWT payload:`, err);
          } else {
            logDebug(`${logPrefix} [INTERNAL] Published JWT payload -> ${internalTopic}`);
          }
        });
      }
      
      callback(null);
    } catch (error) {
      logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JSON or validation error)`);
      callback(new Error('Invalid message format or origin_id validation failed'));
    }
    return;
  }
  
  // Unknown client type
  logInfo(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (unknown client type)`);
  callback(new Error('Unknown client type'));
};

aedes.authorizeSubscribe = (client, subscription, callback) => {
  if (!client) {
    callback(new Error('No client'));
    return;
  }
  
  const logPrefix = getClientLogPrefix(client);
  const clientType = (client as any).clientType;
  
  // Publisher clients cannot subscribe (publish-only) - EXCEPT their own serial/commands topic
  if (clientType === ClientType.PUBLISHER) {
    // Allow publishers to subscribe to their own serial/commands topic for remote serial access
    // Topic format: meshcore/{IATA}/{PUBLIC_KEY}/serial/commands
    if (subscription.topic.endsWith('/serial/commands')) {
      const parts = subscription.topic.split('/');
      if (parts.length === 5 && parts[0] === 'meshcore' && parts[3] === 'serial') {
        const topicPublicKey = parts[2].toUpperCase();
        const clientPublicKey = ((client as any).publicKey || '').toUpperCase();
        // Publisher can only subscribe to their OWN serial/commands topic
        if (topicPublicKey === clientPublicKey && clientPublicKey.length === 64) {
          logInfo(`${logPrefix} [AUTHZ] ✓ Subscribe authorized (own serial/commands) -> ${subscription.topic}`);
          callback(null, subscription);
          return;
        }
      }
    }
    logInfo(`${logPrefix} [AUTHZ] ✗ Subscribe denied (publisher) -> ${subscription.topic}`);
    logInfo(`${logPrefix} [DISCONNECT] Closing client - Publishers cannot subscribe`);
    callback(new Error('Publisher clients are publish-only'));
    client.close();
    return;
  }
  
  // Subscriber clients can subscribe to any topic (they're listeners)
  if (clientType === ClientType.SUBSCRIBER) {
    logInfo(`${logPrefix} [AUTHZ] ✓ Subscribe authorized -> ${subscription.topic}`);
    callback(null, subscription);
    return;
  }
  
  // Unknown client type
  logInfo(`${logPrefix} [AUTHZ] ✗ Subscribe denied -> ${subscription.topic} (unknown client type)`);
  callback(new Error('Unknown client type'));
};

// Track last seen status timestamp per origin_id to prevent race conditions
const lastStatusTimestamps = new Map<string, number>();

// Authorization handler for forwarding messages to subscribers (filter sensitive data)
aedes.authorizeForward = (client, packet) => {
  if (!client) {
    return packet;
  }
  
  const clientType = (client as any).clientType;
  const role = (client as any).role;
  
  // Block $SYS/* messages for non-admin subscribers (only role 1 can see system topics)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.startsWith('$SYS/')) {
      return null; // Block delivery of this message
    }
  }
  
  // Critical: Block /internal topics for non-admin subscribers (contains PII)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.includes('/internal')) {
      return null; // Block delivery of this message
    }
  }
  
  // Block /serial/* topics for non-admin subscribers (remote serial access is admin-only)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.includes('/serial/')) {
      return null; // Block delivery of this message
    }
  }

  // Block /wardriver/* topics for LIMITED subscribers. The wardriver stream is
  // realtime location of identified operators (sensitive), so only FULL_ACCESS and
  // ADMIN receive it; a LIMITED subscriber never does.
  if (clientType === ClientType.SUBSCRIBER && role === SubscriberRole.LIMITED) {
    if (packet.topic.includes('/wardriver/')) {
      return null; // Block delivery of this message
    }
  }

  // Prevent stale status messages from overwriting newer ones (LWT race condition)
  if (packet.topic.endsWith('/status') && packet.payload && packet.payload.length > 0) {
    try {
      const message = JSON.parse(packet.payload.toString());
      const originId = message.origin_id;
      const timestamp = message.timestamp ? new Date(message.timestamp).getTime() : 0;
      
      if (originId && timestamp) {
        const lastTimestamp = lastStatusTimestamps.get(originId) || 0;
        
        if (timestamp < lastTimestamp) {
          // This is a stale status message (probably a delayed LWT)
          logInfo(`[FILTER] Blocking stale status message for ${originId.substring(0, 8)} (${new Date(timestamp).toISOString()} < ${new Date(lastTimestamp).toISOString()})`);
          return null; // Block this stale message
        }
        
        // Update the last seen timestamp
        lastStatusTimestamps.set(originId, timestamp);
      }
    } catch (error) {
      // If parsing fails, let it through (don't block non-JSON status messages)
      logDebug(`[FILTER] Failed to parse status message for timestamp check:`, error);
    }
  }
  
  // Only filter for LIMITED role subscribers (role 3)
  if (clientType === ClientType.SUBSCRIBER && role === SubscriberRole.LIMITED) {
    // Filter status messages (meshcore/*/status) to remove stats, model, and firmware_version
    if (packet.topic.endsWith('/status') && packet.payload && packet.payload.length > 0) {
      try {
        const message = JSON.parse(packet.payload.toString());
        
        // Track if we need to filter anything
        let filtered = false;
        
        // Remove the stats object if it exists
        if (message.stats) {
          delete message.stats;
          filtered = true;
        }
        
        // Remove model if it exists
        if (message.model !== undefined) {
          delete message.model;
          filtered = true;
        }
        
        // Remove firmware_version if it exists
        if (message.firmware_version !== undefined) {
          delete message.firmware_version;
          filtered = true;
        }
        
        // Only create new packet if we actually filtered something
        if (filtered) {
          return {
            ...packet,
            payload: Buffer.from(JSON.stringify(message))
          };
        }
      } catch (error) {
        // If JSON parsing fails, just return the original packet
        logDebug(`[FILTER] Failed to parse status message for filtering:`, error);
      }
    }
    
    // Filter packet messages (meshcore/*/packets) to remove SNR, RSSI, score
    if (packet.topic.endsWith('/packets') && packet.payload && packet.payload.length > 0) {
      try {
        const message = JSON.parse(packet.payload.toString());
        
        // Remove radio metrics if they exist
        let filtered = false;
        if (message.SNR !== undefined) {
          delete message.SNR;
          filtered = true;
        }
        if (message.RSSI !== undefined) {
          delete message.RSSI;
          filtered = true;
        }
        if (message.score !== undefined) {
          delete message.score;
          filtered = true;
        }
        
        // Only create new packet if we actually filtered something
        if (filtered) {
          return {
            ...packet,
            payload: Buffer.from(JSON.stringify(message))
          };
        }
      } catch (error) {
        // If JSON parsing fails, just return the original packet
        logDebug(`[FILTER] Failed to parse packet message for filtering:`, error);
      }
    }
  }
  
  // No filtering needed - return original packet
  return packet;
};

// Event handlers
aedes.on('client', (client) => {
  // Link stream to client if available
  (client as any).stream = (client as any).conn;
  
  const logPrefix = getClientLogPrefix(client);
  logInfo(`${logPrefix} [CLIENT] Connected`);
  logDebug(`${logPrefix} [CLIENT] Connection details - conn exists: ${!!(client as any).conn}, clientIP: ${(client as any).conn?.clientIP}`);
  
  // Track when this client connected for disconnect timing
  (client as any).connectedAt = Date.now();
  
  // Hook into the client's stream close event to see WHO closed it
  const stream = (client as any).stream;
  if (stream) {
    const originalClose = stream.close?.bind(stream);
    const originalDestroy = stream.destroy?.bind(stream);
    
    (stream as any).close = function(...args: any[]) {
      logDebug(`${logPrefix} [STREAM] close() called (server-initiated close)`);
      if (originalClose) originalClose(...args);
    };
    
    (stream as any).destroy = function(...args: any[]) {
      logDebug(`${logPrefix} [STREAM] destroy() called - error: ${args[0]?.message || 'none'}`);
      if (originalDestroy) originalDestroy(...args);
    };
  }
});

aedes.on('clientDisconnect', (client) => {
  const logPrefix = getClientLogPrefix(client);
  const connectedAt = (client as any).connectedAt;
  const duration = connectedAt ? Math.round((Date.now() - connectedAt) / 1000) : 'unknown';
  
  logInfo(`${logPrefix} [CLIENT] Disconnected (connected for ${duration}s)`);
  
  // Log additional info to debug why this client disconnected
  if (client) {
    logDebug(`${logPrefix} [CLIENT] Disconnect details - clientType: ${(client as any).clientType}, publicKey: ${(client as any).publicKey?.substring(0, 8)}`);
    
    // Clean up subscriber connection tracking
    const clientType = (client as any).clientType;
    const username = (client as any).username;
    if (clientType === ClientType.SUBSCRIBER && username) {
      const activeConns = subscriberActiveConnections.get(username);
      if (activeConns) {
        activeConns.delete(client.id);
        const maxConn = subscriberMaxConnections.get(username) || subscriberConfig.defaultMaxConnections;
        logInfo(`${logPrefix} [CLIENT] Subscriber connection removed (${username}, connections: ${activeConns.size}/${maxConn})`);
      }
      connectedSubscribers.delete(client.id);
    }

    if (clientType === ClientType.PUBLISHER) {
      connectedTokenClients.delete(client.id);
    }
  }
});

aedes.on('publish', (packet, client) => {
  if (client) {
    const logPrefix = getClientLogPrefix(client);
    logDebug(`${logPrefix} [PUBLISH] ${packet.topic} (${packet.payload.length} bytes)`);

    const clientType = (client as any).clientType;
    if (clientType === ClientType.PUBLISHER) {
      const payloadLength = packet.payload?.length || 0;
      messagesReceivedTotal += 1;
      messagesReceivedBytesTotal += payloadLength;
      messagesReceivedSinceLastStats += 1;
      messagesReceivedBytesSinceLastStats += payloadLength;

      if (packet.topic.startsWith('meshcore/')) {
        meshcoreMessagesReceivedTotal += 1;
      }
    }
  } else {
    logDebug(`[PUBLISH] Internal -> ${packet.topic} (${packet.payload.length} bytes)`);
  }
});

aedes.on('subscribe', (subscriptions, client) => {
  const logPrefix = getClientLogPrefix(client);
  logInfo(`${logPrefix} [SUBSCRIBE] Attempting to subscribe to: ${subscriptions.map(s => s.topic).join(', ')}`);
});

// Log when client sends DISCONNECT packet (graceful disconnect)
aedes.on('clientError', (client, err) => {
  const logPrefix = getClientLogPrefix(client);
  logInfo(`${logPrefix} [ERROR] Client error: ${err.message}`);
});

// Create HTTP server for WebSocket
const httpServer = createServer((req, res) => {
  // If this is not a WebSocket upgrade request, redirect to the front-end.
  if (!req.headers.upgrade || req.headers.upgrade.toLowerCase() !== 'websocket') {
    logInfo(`[HTTP] Non-WebSocket request from ${getClientIP(req)}, redirecting to ${HTTP_REDIRECT_URL}`);
    res.writeHead(302, { 'Location': HTTP_REDIRECT_URL });
    res.end();
    return;
  }
});

// Server-level 'error' events. Node emits accept() failures (EMFILE/ENFILE/ENOBUFS when the
// process runs out of file descriptors or memory) as 'error' on the listening server; with no
// listener that is an uncaught exception and the whole broker dies for what is a transient,
// per-connection condition. Once listening we therefore log (throttled, as EMFILE can repeat in
// a tight loop) and keep serving; the kernel retries accept on the next connection. Errors
// before listening (EADDRINUSE, EACCES) mean the broker can never work, so those stay fatal.
// The WebSocketServer re-emits every http server error, so a WeakSet avoids logging it twice.
const loggedServerErrors = new WeakSet<object>();
let lastServerErrorLogAt = 0;
function handleServerError(source: string, error: NodeJS.ErrnoException): void {
  if (!httpServer.listening) {
    console.error(`[FATAL] ${source} error before listening:`, error.stack || error);
    process.exit(1);
  }
  if (loggedServerErrors.has(error)) return;
  loggedServerErrors.add(error);
  const now = Date.now();
  if (now - lastServerErrorLogAt >= 5000) {
    lastServerErrorLogAt = now;
    console.error(`[${source}] Server error (${error.code || 'unknown'}), continuing:`, error.message);
  }
}
httpServer.on('error', (error) => handleServerError('HTTP', error));

// Create WebSocket server
const wsServer = new WebSocketServer({ server: httpServer });
wsServer.on('error', (error) => handleServerError('WEBSOCKET', error));

wsServer.on('connection', (ws, req) => {
  try {
    const clientIP = getClientIP(req);
    
    // Check if IP is blocked
    if (rateLimiter.isBlocked(clientIP)) {
      logInfo(`[RATE_LIMIT] Rejecting connection from blocked IP: ${clientIP}`);
      // Terminate immediately without trying to send a close frame
      ws.terminate();
      return;
    }
    
    logInfo(`[WEBSOCKET] New WebSocket connection from ${clientIP}`);
  
  // Enable WebSocket ping/pong to keep connection alive
  ws.on('ping', (data) => {
    logInfo(`[WEBSOCKET] Received WebSocket PING from ${clientIP}, sending PONG`);
    ws.pong(data);
  });
  
  ws.on('pong', () => {
    logInfo(`[WEBSOCKET] Received WebSocket PONG from ${clientIP}`);
  });
  
  // Handle WebSocket errors
  ws.on('error', (error) => {
    // Log other WebSocket errors
    console.error(`[WEBSOCKET] Error from ${clientIP}:`, error.message);
  });
  
  // Create a duplex stream from the WebSocket
  const stream = new Duplex({
    read() {
      // No-op, data is pushed via ws.on('message')
    },
    write(chunk, encoding, callback) {
      if (ws.readyState === ws.OPEN) {
        // Log MQTT PINGRESP packets (0xD0 = PINGRESP)
        if (chunk instanceof Buffer && chunk.length >= 2 && chunk[0] === 0xD0) {
          const clientInfo = (stream as any).client;
          if (clientInfo) {
            const logPrefix = getClientLogPrefix(clientInfo);
            logDebug(`${logPrefix} [MQTT] Sending PINGRESP (PONG) to client`);
          } else {
            logDebug(`[MQTT] Sending PINGRESP (PONG) to unauthenticated client`);
          }
        }
        
        ws.send(chunk, (error) => {
          // Suppress EPIPE errors - they're expected when client disconnects
          if (error && (error as any).code !== 'EPIPE') {
            const clientInfo = (stream as any).client;
            if (clientInfo) {
              const logPrefix = getClientLogPrefix(clientInfo);
              console.error(`${logPrefix} [WEBSOCKET] Send error:`, error);
            } else {
              console.error('[WEBSOCKET] Send error:', error);
            }
          }
          callback(error);
        });
      } else {
        callback(new Error('WebSocket not open'));
      }
    }
  });

  // Forward WebSocket messages to the stream
  ws.on('message', (data) => {
    // Log MQTT PINGREQ packets (0xC0 = PINGREQ) with client identifier
    if (data instanceof Buffer && data.length >= 2 && data[0] === 0xC0) {
      const clientInfo = (stream as any).client;
      if (clientInfo) {
        const logPrefix = getClientLogPrefix(clientInfo);
        logDebug(`${logPrefix} [MQTT] Received PINGREQ (PING) from client`);
      } else {
        logDebug('[MQTT] Received PINGREQ (PING) from unauthenticated client');
      }
    }
    stream.push(data);
  });

  // Store client IP on stream for logging
  (stream as any).clientIP = clientIP;
  (stream as any).authenticated = false;
  
  // Handle WebSocket close
  ws.on('close', (code, reason) => {
    const clientInfo = (stream as any).client;
    const wasAuthenticated = (stream as any).authenticated;
    
    // Check if client properly authenticated (has clientType set)
    const hasValidAuth = clientInfo && (clientInfo as any).clientType;
    
    if (hasValidAuth) {
      const logPrefix = getClientLogPrefix(clientInfo);
      logInfo(`${logPrefix} [WEBSOCKET] Connection closed from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
    } else {
      // Unauthenticated or invalid client - count as failed connection
      logInfo(`[C:${clientInfo?.id || 'null'}] [WEBSOCKET] Connection closed (unauthenticated) from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
      
      if (!wasAuthenticated) {
        const blocked = rateLimiter.recordFailure(clientIP);
        if (blocked) {
          logInfo(`[RATE_LIMIT] IP ${clientIP} has been blocked`);
        }
      }
    }
    stream.push(null);
  });

  // Handle stream end
  stream.on('end', () => {
    const clientInfo = (stream as any).client;
    if (clientInfo) {
      const logPrefix = getClientLogPrefix(clientInfo);
      logInfo(`${logPrefix} [STREAM] Stream ended, closing WebSocket`);
    } else {
      logInfo('[STREAM] Stream ended (unauthenticated), closing WebSocket');
    }
    ws.close();
  });

  // Pass the stream to Aedes
  aedes.handle(stream);
  } catch (error) {
    console.error('[WEBSOCKET] Error handling connection:', error);
    try {
      ws.terminate();
    } catch (e) {
      // Ignore errors when terminating
    }
  }
});

setInterval(publishCollectorStats, STATS_INTERVAL_MS);
setTimeout(publishCollectorStats, 1000);

logInfo(`[STATS] Publishing collector stats every ${STATS_INTERVAL_MS}ms to ${getStatsTopic()} (retain: ${STATS_RETAIN}, token details: ${STATS_INCLUDE_TOKEN_CLIENT_DETAILS})`);

httpServer.listen(WS_PORT, HOST, () => {
  logInfo('╔════════════════════════════════════════════════════════════╗');
  logInfo('║         MeshCore MQTT Broker (WebSocket)                  ║');
  logInfo('╚════════════════════════════════════════════════════════════╝');
  logInfo(`WebSocket MQTT listening on: ws://${HOST}:${WS_PORT}`);
  logInfo('');
  logInfo('Authentication Modes:');
  logInfo(`  1. Subscribers (Subscribe-only): ${subscriberUsers.size} user(s) configured`);
  logInfo('     Usernames:', Array.from(subscriberUsers.keys()).join(', '));
  logInfo('');
  logInfo('  2. Publishers (Publish-only):');
  logInfo('     Username: v1_{PUBLIC_KEY}');
  logInfo('     Password: JWT token signed with Ed25519 private key');
  logInfo('     Validation:');
  logInfo('       - origin_id must match authenticated public key');
  if (EXPECTED_AUDIENCE) {
    logInfo(`       - Token audience must be: ${EXPECTED_AUDIENCE}`);
  }
  logInfo('');
  logInfo('Ready to accept connections...');
});

// Graceful shutdown
process.on('SIGINT', () => {
  logInfo('\n[SHUTDOWN] Closing MQTT broker...');
  abuseDetector.shutdown();
  aedes.close(() => {
    logInfo('[SHUTDOWN] Broker closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  logInfo('\n[SHUTDOWN] Closing MQTT broker...');
  abuseDetector.shutdown();
  aedes.close(() => {
    logInfo('[SHUTDOWN] Broker closed');
    process.exit(0);
  });
});
