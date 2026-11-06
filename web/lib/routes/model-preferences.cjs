'use strict';

const { handle } = require('../http.cjs');
const { createModelPreferences } = require('../model-preferences.cjs');

function registerModelPreferenceRoutes(app, { store }) {
  const preferences = createModelPreferences(store.directory);
  app.get('/api/model-preferences', handle(() => ({ preferences: preferences.read() })));
  app.put('/api/model-preferences', handle(req => ({ preferences: preferences.save(req.body) })));
}

module.exports = { registerModelPreferenceRoutes };
