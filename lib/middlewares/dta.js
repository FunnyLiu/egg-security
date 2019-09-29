'use strict';

// https://en.wikipedia.org/wiki/Directory_traversal_attack
const isSafePath = require('../utils').isSafePath;

module.exports = () => {
  return function dta(ctx, next) {
    const path = ctx.path;
    // 判断是否是安全的路径，不带../等
    if (!isSafePath(path, ctx)) {
      ctx.throw(400);
    }
    return next();
  };
};
