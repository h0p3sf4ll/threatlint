'use strict';

const fs = require('node:fs');

async function convertToWord(_mdPath, docxPath) {
  fs.writeFileSync(docxPath, 'PK-docx');
}

module.exports = { convertToWord };
