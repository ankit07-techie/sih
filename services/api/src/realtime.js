/**
 * PassiveShield AI — Real-Time Socket.IO Alert Delivery Service
 * Manages WebSocket client connections and streams standardized ThreatAlert payloads in real-time over the 'alert:new' event topic.
 */

const { Server } = require('socket.io');

/**
 * Initializes Socket.IO server bound to an HTTP server instance.
 * @param {import('http').Server} httpServer
 * @returns {{ io: Server, broadcastAlert: Function, getConnectedClientCount: Function }}
 */
function setupRealtimeServer(httpServer) {
  const io = new Server(httpServer, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST']
    },
    transports: ['websocket', 'polling']
  });

  io.on('connection', (socket) => {
    console.log(`[Realtime] Client connected: ${socket.id}`);

    // Welcome greeting
    socket.emit('system:info', {
      message: 'Connected to PassiveShield AI Real-Time Alert Stream',
      timestamp: new Date().toISOString(),
      socket_id: socket.id
    });

    // Health check ping/pong
    socket.on('ping', () => {
      socket.emit('pong', { timestamp: new Date().toISOString() });
    });

    socket.on('disconnect', (reason) => {
      console.log(`[Realtime] Client disconnected: ${socket.id} (${reason})`);
    });
  });

  /**
   * Broadcasts a standardized ThreatAlert object to all connected WebSocket clients.
   * @param {Object} threatAlert
   */
  function broadcastAlert(threatAlert) {
    if (!threatAlert || typeof threatAlert !== 'object') {
      console.error('[Realtime] Invalid threat alert payload for broadcast:', threatAlert);
      return false;
    }

    io.emit('alert:new', threatAlert);
    console.log(`[Realtime] Broadcasted ThreatAlert '${threatAlert.alert_id || 'unknown'}' to ${io.sockets.sockets.size} clients.`);
    return true;
  }

  function getConnectedClientCount() {
    return io.sockets.sockets.size;
  }

  return {
    io,
    broadcastAlert,
    getConnectedClientCount
  };
}

module.exports = setupRealtimeServer;
