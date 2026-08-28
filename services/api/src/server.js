/**
 * PassiveShield AI — Express Server Entrypoint
 */

const app = require('./app');

const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, () => {
  console.log(`PassiveShield AI Express API Gateway listening on port ${PORT}`);
});

module.exports = server;
