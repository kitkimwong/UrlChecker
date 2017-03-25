    function isURL(url, options) {
        assertString(url);
        if (!url || url.length >= 2083 || /[\s<>]/.test(url)) {
          return false;
        }
        if (url.indexOf('mailto:') === 0) {
          return false;
        }
        options = merge(options, default_url_options);
        var protocol = void 0,
            auth = void 0,
            host = void 0,
            hostname = void 0,
            port = void 0,
            port_str = void 0,
            split = void 0,
            ipv6 = void 0;

        split = url.split('#');
        url = split.shift();

        split = url.split('?');
        url = split.shift();

        split = url.split('://');
        if (split.length > 1) {
          protocol = split.shift();
          if (options.require_valid_protocol && options.protocols.indexOf(protocol) === -1) {
            return false;
          }
        } else if (options.require_protocol) {
          return false;
        } else if (options.allow_protocol_relative_urls && url.substr(0, 2) === '//') {
          split[0] = url.substr(2);
        }
        url = split.join('://');

        split = url.split('/');
        url = split.shift();

        if (url === '' && !options.require_host) {
          return true;
        }

        split = url.split('@');
        if (split.length > 1) {
          auth = split.shift();
          if (auth.indexOf(':') >= 0 && auth.split(':').length > 2) {
            return false;
          }
        }
        hostname = split.join('@');

        port_str = ipv6 = null;
        var ipv6_match = hostname.match(wrapped_ipv6);
        if (ipv6_match) {
          host = '';
          ipv6 = ipv6_match[1];
          port_str = ipv6_match[2] || null;
        } else {
          split = hostname.split(':');
          host = split.shift();
          if (split.length) {
            port_str = split.join(':');
          }
        }

        if (port_str !== null) {
          port = parseInt(port_str, 10);
          if (!/^[0-9]+$/.test(port_str) || port <= 0 || port > 65535) {
            return false;
          }
        }

        if (!isIP(host) && !isFDQN(host, options) && (!ipv6 || !isIP(ipv6, 6)) && host !== 'localhost') {
          return false;
        }

        host = host || ipv6;

        if (options.host_whitelist && !checkHost(host, options.host_whitelist)) {
          return false;
        }
        if (options.host_blacklist && checkHost(host, options.host_blacklist)) {
          return false;
        }

        return true;
      }
      
      
      function isIP(str) {
        var version = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';

        assertString(str);
        version = String(version);
        if (!version) {
          return isIP(str, 4) || isIP(str, 6);
        } else if (version === '4') {
          if (!ipv4Maybe.test(str)) {
            return false;
          }
          var parts = str.split('.').sort(function (a, b) {
            return a - b;
          });
          return parts[3] <= 255;
        } else if (version === '6') {
          var blocks = str.split(':');
          var foundOmissionBlock = false; // marker to indicate ::

          // At least some OS accept the last 32 bits of an IPv6 address
          // (i.e. 2 of the blocks) in IPv4 notation, and RFC 3493 says
          // that '::ffff:a.b.c.d' is valid for IPv4-mapped IPv6 addresses,
          // and '::a.b.c.d' is deprecated, but also valid.
          var foundIPv4TransitionBlock = isIP(blocks[blocks.length - 1], 4);
          var expectedNumberOfBlocks = foundIPv4TransitionBlock ? 7 : 8;

          if (blocks.length > expectedNumberOfBlocks) {
            return false;
          }
          // initial or final ::
          if (str === '::') {
            return true;
          } else if (str.substr(0, 2) === '::') {
            blocks.shift();
            blocks.shift();
            foundOmissionBlock = true;
          } else if (str.substr(str.length - 2) === '::') {
            blocks.pop();
            blocks.pop();
            foundOmissionBlock = true;
          }

          for (var i = 0; i < blocks.length; ++i) {
            // test for a :: which can not be at the string start/end
            // since those cases have been handled above
            if (blocks[i] === '' && i > 0 && i < blocks.length - 1) {
              if (foundOmissionBlock) {
                return false; // multiple :: in address
              }
              foundOmissionBlock = true;
            } else if (foundIPv4TransitionBlock && i === blocks.length - 1) {
              // it has been checked before that the last
              // block is a valid IPv4 address
            } else if (!ipv6Block.test(blocks[i])) {
              return false;
            }
          }
          if (foundOmissionBlock) {
            return blocks.length >= 1;
          }
          return blocks.length === expectedNumberOfBlocks;
        }
        return false;
      }

      
      
      var wrapped_ipv6 = /^\[([^\]]+)\](?::([0-9]+))?$/;
      
      var default_url_options = {
        protocols: ['http', 'https', 'ftp'],
        require_tld: true,
        require_protocol: false,
        require_host: true,
        require_valid_protocol: true,
        allow_underscores: false,
        allow_trailing_dot: false,
        allow_protocol_relative_urls: false
      };
      
            function isFDQN(str, options) {
        assertString(str);
        options = merge(options, default_fqdn_options);

        /* Remove the optional trailing dot before checking validity */
        if (options.allow_trailing_dot && str[str.length - 1] === '.') {
          str = str.substring(0, str.length - 1);
        }
        var parts = str.split('.');
        if (options.require_tld) {
          var tld = parts.pop();
          if (!parts.length || !/^([a-z\u00a1-\uffff]{2,}|xn[a-z0-9-]{2,})$/i.test(tld)) {
            return false;
          }
        }
        for (var part, i = 0; i < parts.length; i++) {
          part = parts[i];
          if (options.allow_underscores) {
            part = part.replace(/_/g, '');
          }
          if (!/^[a-z\u00a1-\uffff0-9-]+$/i.test(part)) {
            return false;
          }
          if (/[\uff01-\uff5e]/.test(part)) {
            // disallow full-width chars
            return false;
          }
          if (part[0] === '-' || part[part.length - 1] === '-') {
            return false;
          }
        }
        return true;
      }
      
            var default_fqdn_options = {
        require_tld: true,
        allow_underscores: false,
        allow_trailing_dot: false
      };
      
      var ipv4Maybe = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
      var ipv6Block = /^[0-9A-F]{1,4}$/i;
      
      function assertString(input) {
        if (typeof input !== 'string') {
          throw new TypeError('This library (validator.js) validates strings only');
        }
      }


      function merge() {
        var obj = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
        var defaults = arguments[1];

        for (var key in defaults) {
          if (typeof obj[key] === 'undefined') {
            obj[key] = defaults[key];
          }
        }
        return obj;
      }
      
