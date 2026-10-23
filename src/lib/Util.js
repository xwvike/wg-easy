'use strict';

const childProcess = require('child_process');

const IPV4_OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_REGEX = new RegExp(`^(${IPV4_OCTET}\\.){3}${IPV4_OCTET}$`);

function __ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

function __intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

module.exports = class Util {

  static isValidIPv4(str) {
    return typeof str === 'string' && IPV4_REGEX.test(str);
  }

  static networkAddress(ip, cidr) {
    const mask = cidr === 0 ? 0 : (~0 << (32 - cidr)) >>> 0;
    return __intToIp((__ipToInt(ip) & mask) >>> 0);
  }

  static cidrOverlaps(a, b) {
    const cidr = Math.min(a.cidr, b.cidr);
    return Util.networkAddress(a.address, cidr) === Util.networkAddress(b.address, cidr);
  }

  static validateAllowedIP({ address: ip, cidr }) {
    const ipCidr = `${ip}/${cidr}`;

    if (!Util.isValidIPv4(ip)) {
      return `Invalid IP address: ${ip}`;
    }

    if (!Number.isInteger(cidr) || cidr < 0 || cidr > 32) {
      return `Invalid subnet mask: ${ipCidr}`;
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
