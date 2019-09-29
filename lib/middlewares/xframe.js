'use strict';

const utils = require('../utils');

module.exports = options => {
  return async function xframe(ctx, next) {
    await next();

    const opts = utils.merge(options, ctx.securityOptions.xframe);
    if (utils.checkIfIgnore(opts, ctx)) return;

    // DENY,SAMEORIGIN,ALLOW-FROM
    // https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options?redirectlocale=en-US&redirectslug=The_X-FRAME-OPTIONS_response_header
    const value = opts.value || 'SAMEORIGIN';
    // 给浏览器指示允许一个页面可否在 <frame>, <iframe>, <embed> 或者 <object> 中展现的标记
    ctx.set('x-frame-options', value);
  };
};
