'use strict';
// stdout belongs exclusively to the MCP protocol. Workbench services use their existing local profile.
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const workbench = require('../server.js');
const server = workbench.createMcpServer();
let closing = false;
async function close() { if (closing) return; closing = true; await server.close(); await workbench.close(); }
process.once('SIGINT', () => { void close(); });
process.once('SIGTERM', () => { void close(); });
process.stdin.once('end', () => { void close(); });
server.connect(new StdioServerTransport()).catch(async () => { console.error('Threatlint MCP could not start'); await close(); process.exitCode = 1; });
