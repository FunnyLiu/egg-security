'use strict';

const statuses = require('statuses');
const utils = require('../utils');

module.exports = options => {
  return async function nosniff(ctx, next) {
    await next();

    // ignore redirect response
    if (statuses.redirect[ctx.status]) return;

    const opts = utils.merge(options, ctx.securityOptions.nosniff);
    if (utils.checkIfIgnore(opts, ctx)) return;
    // 提示客户端一定要遵循在 Content-Type 首部中对  MIME 类型 的设定，而不能对其进行修改
    ctx.set('x-content-type-options', 'nosniff');
  };
};
