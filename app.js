const radius = require('radius');
const dgram = require('dgram');

const handlers = require('./handlers');
const helper = require('./helper');

const secret = 'secret';
const authServer = dgram.createSocket('udp4');
const acctServer = dgram.createSocket('udp4');

function makeFailedResponse(packet, secret, failedMessage) {
    return {
        packet: packet,
        code: 'Access-Reject',
        secret: secret,
        attributes: [
            ['Reply-Message', failedMessage],
        ]
    };
}

authServer.on('message', (msg, req) => {
    let packet = radius.decode({packet: msg, secret});
    // console.log(packet);

    if (packet.code === 'Access-Request') {

        const username = packet.attributes['User-Name'];
        helper.httpGetJson('http://localhost:3000/?username='+username).then(userInfo => {
            let msResponse;

            if (userInfo && userInfo.password) {

                [   handlers.PapAuthHandler,
                    handlers.ChapAuthHandler,
                    handlers.MSChapV1AuthHandler,
                    handlers.MSChapV2AuthHandler].some(handlerClass => {
                    let handler = new handlerClass(packet, secret, username, userInfo.password);
                    if (handler.authable()) {
                        let args = handler.check();
                        args.attributes.push(['Framed-IP-Address', userInfo.ip]);
                        args.attributes.push(['Session-Timeout', userInfo.timeout]);
                        msResponse = radius.encode_response(args);
                        return true;
                    }
                });

                if (!msResponse) {
                    msResponse = radius.encode_response(makeFailedResponse(packet, secret, 'Unknown auth type'));
                }
            } else {
                msResponse = radius.encode_response(makeFailedResponse(packet, secret, 'Unknown user'));
            }

            authServer.send(msResponse, 0, msResponse.length, req.port, req.address, (err, bytes) => {
                if (err) {
                    console.log('Error sending response to ', req);
                }
            });
        }).catch(reason => {
            console.log(reason);
        });
    } else {
        console.log('Unknown packet type: ', packet.code);
    }
});

authServer.on("listening", function () {
    let address = authServer.address();
    console.log("radius authenticating server listening " +
        address.address + ":" + address.port);
});
authServer.bind(1812);

acctServer.on("message", function (msg, rinfo) {

    console.log('acct: ', msg);authcating
    let code, username, password, packet;
    packet = radius.decode({packet: msg, secret: secret});

    console.log('acct: ', packet.code);
});



acctServer.on("listening", function () {
    let address = acctServer.address();
    console.log("radius accounting server listening " +
        address.address + ":" + address.port);
});

acctServer.bind(1813);