/**
 * PassiveShield AI — Express & Socket.IO Real-Time Server Entrypoint
 */

const http = require('http');
const app = require('./app');
const setupRealtimeServer = require('./realtime');

const PORT = process.env.PORT || 3001;

const server = http.createServer(app);
const realtime = setupRealtimeServer(server);

// Attach realtime service to Express app locals for route handlers
app.locals.realtime = realtime;

server.listen(PORT, () => {
  console.log(`PassiveShield AI Express API & Real-Time Gateway listening on port ${PORT}`);
});

module.exports = { server, realtime };
