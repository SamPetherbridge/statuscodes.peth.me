import { getAssetFromKV, mapRequestToAsset } from '@cloudflare/kv-asset-handler'

addEventListener('fetch', event => {
  try {
    event.respondWith(handleEvent(event))
  } catch (e) {
    event.respondWith(new Response('Internal Error', { status: 500 }))
  }
})

async function handleEvent(event) {
  try {
    let url = new URL(event.request.url);
    let options = {}

    // Check to see if the regex match to 3 digets
    let regex = /^\/[0-9]{3}.*$/gm;
    if (regex.exec(url.pathname) !== null) {
      // We have a Regex Match to /xxx send to status code response
      return statusCodeResponse(event)
    } else {
      if (url.pathname === '/random') {
        let randomStatusList = ['200', '204', '400', '403', '404', '500', '503']
        return respondWithStatusCode(randomStatusList[Math.floor(Math.random() * randomStatusList.length)], respondSecure(event), includeBody(event))
      } else {
        try {
          let response = await getAssetFromKV(event, options);
          response = new Response(response.body, { ...response});
          response = addSecurityHeaders(response)
          return response
        } catch (e) {
          try {
            let notFoundResponse = await getAssetFromKV(event, {
              mapRequestToAsset: req => new Request(`${new URL(req.url).origin}/404.html`, req),
            })

            let response = new Response(notFoundResponse.body, { ...notFoundResponse, status: 404 });
            response = addSecurityHeaders(response);
            return response
          } catch (e) {
            return new Response(e.message || e.toString(), { status: 500 })
          }
        }
      }
    }

  } catch (e) {
    return new Response(e.message || e.toString(), { status: 500 })
  }
}

function respondSecure(event) {
  try {
    let url = new URL(event.request.url);
    // Check to see if we are working of https
    if (url.toString().startsWith('https:')) {
      return true;
    } else {
      return false;
    }
  } catch (e) {
    return addSecurityHeaders(new Response(e.message || e.toString(), { status: 500 }))
  }
}

function includeBody(event) {
  try {
    // Check to see the request type is not head.
    if (event.request.method === 'HEAD') {
      return false
    }
    let url = new URL(event.request.url);
    if (url.searchParams.has('body')) {
      if (url.searchParams.get('body') === 'true') {
        return true
      } else {
        return false
      }
    } else {
      return true
    }
  } catch (error) {
    return addSecurityHeaders(new Response(e.message || e.toString(), { status: 500 }))
  }
}

function statusCodeResponse(event) {
  try {
    let url = new URL(event.request.url);
    let statusCode = url.pathname.substring(1,4)

    return respondWithStatusCode(statusCode, respondSecure(event), includeBody(event))
  } catch (e) {
    return new Response(e.message || e.toString(), { status: 500 })
  }
}

function respondWithStatusCode(statusCode, secureRequest, includeBody) {
  try {
    var statusCodes = {
      '200' : {'code' : 200, 'description': '200 OK'},
      '201' : {'code' : 201, 'description': '201 CREATED'},
      '202' : {'code' : 202, 'description': '202 Accepted'},
      '203' : {'code' : 203, 'description': '203 Non-Authoritative Information'},
      '204' : {'code' : 204, 'description': '204 No Content', 'response body permitted' : false},
      '205' : {'code' : 205, 'description': '205 Reset Content', 'response body permitted' : false},
      '206' : {'code' : 206, 'description': '206 Partial Content'},
      '207' : {'code' : 207, 'description': '207 Multi-Status'},
      '208' : {'code' : 208, 'description': '208 Already Reported'},
      '226' : {'code' : 226, 'description': '226 IM Used'},
      '300' : {'code' : 300, 'description': '300 Multiple Choices'},
      '301' : {'code' : 301, 'description': '301 Moved Permanently'},
      '302' : {'code' : 302, 'description': '302 Found'},
      '303' : {'code' : 303, 'description': '303 See Other'},
      '304' : {'code' : 304, 'description': '304 Not Modified', 'response body permitted' : false},
      '307' : {'code' : 307, 'description': '307 Temporary Redirect'},
      '308' : {'code' : 308, 'description': '308 Permanent Redirect'},
      '400' : {'code' : 400, 'description': '400 Bad Request'},
      '401' : {'code' : 401, 'description': '401 Unauthorized'},
      '402' : {'code' : 402, 'description': '402 Payment Required'},
      '403' : {'code' : 403, 'description': '403 Forbidden'},
      '404' : {'code' : 404, 'description': '404 Not Found'},
      '405' : {'code' : 405, 'description': '405 Method Not Allowed'},
      '406' : {'code' : 406, 'description': '406 Not Acceptable'},
      '407' : {'code' : 407, 'description': '407 Proxy Authentication Required'},
      '408' : {'code' : 408, 'description': '408 Request Timeout'},
      '409' : {'code' : 409, 'description': '409 Conflict'},
      '410' : {'code' : 410, 'description': '410 Gone'},
      '411' : {'code' : 411, 'description': '411 Length Required'},
      '412' : {'code' : 412, 'description': '412 Precondition Failed'},
      '413' : {'code' : 413, 'description': '413 Payload Too Large'},
      '414' : {'code' : 414, 'description': '414 URI Too Long'},
      '415' : {'code' : 415, 'description': '415 Unsupported Media Type'},
      '416' : {'code' : 416, 'description': '416 Range Not Satisfiable'},
      '417' : {'code' : 417, 'description': '417 Expectation Failed'},
      '418' : {'code' : 418, 'description': "418 I'm a teapot"},
      '421' : {'code' : 421, 'description': '421 Misdirected Request'},
      '422' : {'code' : 422, 'description': '422 Unprocessable Entity'},
      '423' : {'code' : 423, 'description': '423 Locked'},
      '424' : {'code' : 424, 'description': '424 Failed Dependency'},
      '425' : {'code' : 425, 'description': '425 Too Early'},
      '426' : {'code' : 426, 'description': '426 Upgrade Required'},
      '428' : {'code' : 428, 'description': '428 Precondition Required'},
      '429' : {'code' : 429, 'description': '429 Too Many Requests'},
      '431' : {'code' : 431, 'description': '431 Request Header Fields Too Large'},
      '451' : {'code' : 451, 'description': '451 Unavailable For Legal Reasons'},
      '500' : {'code' : 500, 'description': '500 Internal Server Error'},
      '501' : {'code' : 501, 'description': '501 Not Implemented'},
      '502' : {'code' : 502, 'description': '502 Bad Gateway'},
      '503' : {'code' : 503, 'description': '503 Service Unavailable'},
      '504' : {'code' : 504, 'description': '504 Gateway Timeout'},
      '505' : {'code' : 505, 'description': '505 HTTP Version Not Supported'},
      '506' : {'code' : 506, 'description': '506 Variant Also Negotiates'},
      '507' : {'code' : 507, 'description': '507 Insufficient Storage'},
      '508' : {'code' : 508, 'description': '508 Loop Detected'},
      '509' : {'code' : 509, 'description': '509 Bandwidth Limit Exceeded'},
      '510' : {'code' : 510, 'description': '510 Not Extended'},
      '511' : {'code' : 511, 'description': '511 Network Authentication Required'},
      '520' : {'code' : 520, 'description': '520 Origin Error'},
      '521' : {'code' : 521, 'description': '521 Web server is down'},
      '522' : {'code' : 522, 'description': '522 Connection timed out'},
      '523' : {'code' : 523, 'description': '523 Proxy Declined Request'},
      '524' : {'code' : 524, 'description': '524 A timeout occurred'},
      '525' : {'code' : 525, 'description': '525 SSL Handshake Failed'},
      '526' : {'code' : 526, 'description': '526 Invalid SSL Certificate'},
      '527' : {'code' : 527, 'description': '527 Railgun Error'},
      '530' : {'code' : 530, 'description': '530'},
      '598' : {'code' : 598, 'description': '598 Network read timeout error'},
      '599' : {'code' : 599, 'description': '599 Network connect timeout error'},
    };

    if (statusCode in statusCodes) {
      return respond(statusCodes[statusCode], includeBody, secureRequest);
    } else {
      return respond(statusCodes['501'], includeBody, secureRequest);
    }
  } catch (e) {
    return addSecurityHeaders(new Response(e.message || e.toString(), { status: 500 }));
  }
}

function respond(statusCode, includeBody, secureRequest) {
  if ('response body permitted' in statusCode) {
    if (statusCode['response body permitted'] === false) {
      includeBody = false
    }
  }
  if (includeBody) {
    var response = new Response(statusCode['description'], {status: statusCode['code']});
  } else {
    var response = new Response(null, {status: statusCode['code']});
  }

  if (secureRequest) {
    response = addSecurityHeaders(response)
  }

  return response;
}

function addSecurityHeaders(response) {
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  response.headers.set('X-Xss-Protection', '1; mode=block');
  response.headers.set('Feature-Policy',"accelerometer 'none'; camera 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; payment 'none'; usb 'none'");
  response.headers.set('Content-Security-Policy', "default-src 'self' 'unsafe-inline'");
  response.headers.set('X-Frame-Options', "SAMEORIGIN");
  response.headers.set('Access-Control-Allow-Origin', "*");
  return response
}