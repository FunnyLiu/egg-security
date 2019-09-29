'use strict';

const utils = require('../utils');

module.exports = options => {
  return async function xssProtection(ctx, next) {
    await next();

    const opts = utils.merge(options, ctx.securityOptions.xssProtection);
    if (utils.checkIfIgnore(opts, ctx)) return;
    //当检测到跨站脚本攻击 (XSS)时，浏览器将停止加载页面。虽然这些保护在现代浏览器中基本上是不必要的，当网站实施一个强大的Content-Security-Policy来禁用内联的JavaScript ('unsafe-inline')时, 他们仍然可以为尚不支持 CSP 的旧版浏览器的用户提供保护。
    ctx.set('x-xss-protection', opts.value);
  };
};
