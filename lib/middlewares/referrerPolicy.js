'use strict';

const utils = require('../utils');
// https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Referrer-Policy
const ALLOWED_POLICIES_ENUM = [
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
  '',
];

module.exports = options => {
  return async function referrerPolicy(ctx, next) {
    await next();

    const opts = utils.merge(options, ctx.securityOptions.refererPolicy);
    if (utils.checkIfIgnore(opts, ctx)) { return; }
    const policy = opts.value;
    if (!ALLOWED_POLICIES_ENUM.includes(policy)) {
      throw new Error('"' + policy + '" is not available."');
    }
    // 用来监管哪些访问来源信息——会在 Referer  中发送——应该被包含在生成的请求当中。
    ctx.set('referrer-policy', policy);
  };
};
