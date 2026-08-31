/**
 * PassiveShield AI — Centralized Frontend Socket.IO Service
 * Subscribes to real-time 'alert:new' events broadcast from the Express/Socket.IO backend.
 */

import { io } from 'socket.io-client';

const SOCKET_URL = process.env.NEXT_PUBLIC_PASSIVESHIELD_SOCKET_URL || 'http://localhost:3001';

export function createPassiveShieldSocket({ onAlert, onConnect, onDisconnect } = {}) {
  if (typeof window === 'undefined') {
    return {
      connected: false,
      close: () => {},
      ping: () => {}
    };
  }

  const socket = io(SOCKET_URL, {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 1000,
    timeout: 5000
  });

  socket.on('connect', () => {
    console.log(`[PassiveShield Socket] Connected to ${SOCKET_URL} (ID: ${socket.id})`);
    if (onConnect) onConnect(socket.id);
  });

  socket.on('system:info', (info) => {
    console.log('[PassiveShield Socket] Received system:info:', info);
  });

  socket.on('alert:new', (alertPayload) => {
    console.log('[PassiveShield Socket] Live ThreatAlert received:', alertPayload?.alert_id);
    if (onAlert) onAlert(alertPayload);
  });

  socket.on('disconnect', (reason) => {
    console.log('[PassiveShield Socket] Disconnected:', reason);
    if (onDisconnect) onDisconnect(reason);
  });

  return {
    socket,
    get connected() {
      return socket.connected;
    },
    ping: () => socket.emit('ping'),
    close: () => {
      socket.disconnect();
    }
  };
}
