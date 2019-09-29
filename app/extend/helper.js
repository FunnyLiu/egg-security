'use strict';

const helpers = require('../../lib/helper');
// 将lib下helper批量暴露
for (const name in helpers) {
  exports[name] = helpers[name];
}
