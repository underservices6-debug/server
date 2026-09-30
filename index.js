require('dotenv').config();
const { initDatabase } = require('./src/db');
const { createApp } = require('./src/server');

// initialize database, schema, and bootstrap admin
initDatabase();

const app = createApp();
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`[license server] running on http://localhost:${PORT}`);
  console.log(`[license server] admin panel available at http://localhost:${PORT}/login`);
});
