'use strict';

const { handle } = require('../http.cjs');
const { createUiPreferences } = require('../ui-preferences.cjs');

function registerUiPreferenceRoutes(app, { store }) {
  const preferences = createUiPreferences(store.directory);
  app.get('/api/ui-preferences', handle(() => ({ preferences: preferences.read() })));
  app.put('/api/ui-preferences', handle(req => ({ preferences: preferences.save(req.body) })));
}

module.exports = { registerUiPreferenceRoutes };
