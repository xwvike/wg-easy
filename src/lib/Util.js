'use strict';

const childProcess = require('child_process');

function __ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
}
module.exports = class Util {

  static isValidIPv4(str) {
    const blocks = str.split('.');
    if (blocks.length !== 4) return false;

    for (let value of blocks) {
      value = parseInt(value, 10);
      if (Number.isNaN(value)) return false;
      if (value < 0 || value > 255) return false;
    }

    return true;
  }

  static validateAllowedIP(ipCidr) {
    const [ip, cidrStr] = ipCidr.split('/');
    const cidr = cidrStr ? parseInt(cidrStr, 10) : 32;

    if (!Util.isValidIPv4(ip)) {
      return `Invalid IP address: ${ip}`;
    }

    const bannedIPs = new Set([
      '0.0.0.0', '255.255.255.255', '127.0.0.1',
      '10.0.0.1', '172.16.0.1',
    ]);

    if (bannedIPs.has(ip) || ip.endsWith('.255')) {
      return `Dangerous IP address not allowed: ${ip}`;
    }

    if (cidr < 24) {
      return `Subnet mask too broad: ${ipCidr}`;
    }

    // 判断是否在 172.16.0.0/12（Docker 默认桥接网段）
    const ipNum = __ipToInt(ip);
    const dockerStart = __ipToInt('172.16.0.0');
    const dockerEnd = __ipToInt('172.31.255.255');
    if (ipNum >= dockerStart && ipNum <= dockerEnd) {
      return `IP in Docker default network is not allowed: ${ipCidr}`;
    }
    return '';
  }

  static promisify(fn) {
    // eslint-disable-next-line func-names
    return function(req, res) {
      Promise.resolve().then(async () => fn(req, res))
        .then((result) => {
          if (res.headersSent) return;

          if (typeof result === 'undefined') {
            return res
              .status(204)
              .end();
          }

          return res
            .status(200)
            .json(result);
        })
        .catch((error) => {
          if (typeof error === 'string') {
            error = new Error(error);
          }

          // eslint-disable-next-line no-console
          console.error(error);

          return res
            .status(error.statusCode || 500)
            .json({
              error: error.message || error.toString(),
              stack: error.stack,
            });
        });
    };
  }

  static async exec(cmd, {
    log = true,
  } = {}) {
    if (typeof log === 'string') {
      // eslint-disable-next-line no-console
      console.log(`$ ${log}`);
    } else if (log === true) {
      // eslint-disable-next-line no-console
      console.log(`$ ${cmd}`);
    }

    if (process.platform !== 'linux') {
      return '';
    }

    return new Promise((resolve, reject) => {
      childProcess.exec(cmd, {
        shell: 'bash',
      }, (err, stdout) => {
        if (err) return reject(err);
        return resolve(String(stdout).trim());
      });
    });
  }

};
