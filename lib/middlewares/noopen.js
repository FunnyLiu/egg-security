'use strict';

const utils = require('../utils');

// @see http://blogs.msdn.com/b/ieinternals/archive/2009/06/30/internet-explorer-custom-http-headers.aspx
module.exports = options => {
  return async function noopen(ctx, next) {
    await next();

    const opts = utils.merge(options, ctx.securityOptions.noopen);
    if (utils.checkIfIgnore(opts, ctx)) return;
    // 用于指定IE 8以上版本的用户不打开文件而直接保存文件。在下载对话框中不显示“打开”选项。
    ctx.set('x-download-options', 'noopen');
  };
};
