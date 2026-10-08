'use strict';
const { arrancar } = require('./src/server/index.js');
arrancar().catch((e) => {
  console.error('\n  No se pudo arrancar netlab:', e.message, '\n');
  process.exit(1);
});
